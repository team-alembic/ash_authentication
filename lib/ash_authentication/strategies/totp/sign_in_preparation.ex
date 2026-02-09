# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.SignInPreparation do
  @moduledoc """
  Preparation for the TOTP sign-in action.

  Verifies the TOTP code against the user's secret and generates a token
  on successful authentication.

  ## Replay Attack Protection

  TOTP codes can only be used once. After a successful authentication, the
  `last_totp_at` field is updated to the code's timestamp to prevent replay
  attacks. This update is performed atomically with a filter condition to
  prevent race conditions where concurrent requests could both use the same code.
  """
  use Ash.Resource.Preparation
  require Ash.Expr
  alias Ash.{Changeset, Query, Resource}
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt}
  alias AshAuthentication.Strategy.Totp.Helpers

  @doc false
  @impl true
  def prepare(query, opts, context) do
    with {:ok, strategy} <- Info.find_strategy(query, context, opts),
         {:ok, identity} <- Query.fetch_argument(query, strategy.identity_field),
         {:ok, totp_code} <- Query.fetch_argument(query, :code) do
      query =
        query
        |> Query.filter(^ref(strategy.identity_field) == ^identity)
        |> Query.filter(not is_nil(^ref(strategy.secret_field)))

      query
      |> Query.before_action(fn query ->
        Query.ensure_selected(query, [strategy.read_secret_from, strategy.last_totp_at_field])
      end)
      |> Query.after_action(fn
        query, [record] when is_binary(:erlang.map_get(strategy.read_secret_from, record)) ->
          verify_and_authenticate(record, totp_code, query, strategy, context)

        query, [] ->
          {:error, auth_failed(strategy, query, "Query returned no users")}

        query, users when is_list(users) ->
          {:error, auth_failed(strategy, query, "Query returned too many users")}
      end)
    else
      # Arguments not yet available (e.g., during form building) - return query unchanged
      :error -> query
    end
  end

  defp verify_and_authenticate(record, totp_code, query, strategy, context) do
    with :ok <- Helpers.validate_totp_code(totp_code),
         :ok <- verify_totp_code(record, totp_code, strategy) do
      complete_authentication(record, query, strategy, context)
    else
      {:error, :invalid_format} ->
        {:error, auth_failed(strategy, query, "Invalid TOTP code format")}

      {:error, :invalid_code} ->
        {:error, auth_failed(strategy, query, "Invalid TOTP code")}
    end
  end

  defp verify_totp_code(record, totp_code, strategy) do
    secret = Map.get(record, strategy.read_secret_from)
    last_totp_at = Helpers.datetime_to_unix(Map.get(record, strategy.last_totp_at_field))

    if Helpers.valid_totp?(secret, totp_code, strategy, since: last_totp_at) do
      :ok
    else
      {:error, :invalid_code}
    end
  end

  defp complete_authentication(record, query, strategy, context) do
    opts = Ash.Context.to_opts(context)
    code_timestamp = current_code_timestamp(strategy.period)

    case atomic_update_last_totp_at(record, strategy, code_timestamp, opts) do
      {:ok, record} ->
        {:ok, [maybe_generate_token(record, strategy, opts)]}

      {:error, :code_already_used} ->
        {:error, auth_failed(strategy, query, "TOTP code has already been used")}

      {:error, error} ->
        {:error, error}
    end
  end

  defp auth_failed(strategy, query, message) do
    AuthenticationFailed.exception(
      strategy: strategy,
      query: query,
      caused_by: %{
        module: __MODULE__,
        strategy: strategy,
        action: :sign_in,
        message: message
      }
    )
  end

  defp atomic_update_last_totp_at(record, strategy, code_timestamp, opts) do
    # Use atomic update with filter to prevent race conditions.
    # The filter ensures only one concurrent request can succeed with the same code.
    code_datetime = DateTime.from_unix!(code_timestamp)
    last_totp_at_field = strategy.last_totp_at_field

    record
    |> Changeset.new()
    |> Changeset.set_context(%{private: %{ash_authentication?: true}})
    |> Changeset.for_update(:update, %{})
    |> Changeset.filter(
      Ash.Expr.expr(
        is_nil(^ref(last_totp_at_field)) or
          ^ref(last_totp_at_field) < ^code_datetime
      )
    )
    |> Changeset.force_change_attribute(last_totp_at_field, code_datetime)
    |> Ash.update(opts)
    |> case do
      {:ok, updated} ->
        {:ok, updated}

      {:error, %Ash.Error.Invalid{errors: errors}} ->
        if Enum.any?(errors, &match?(%Ash.Error.Changes.StaleRecord{}, &1)) do
          {:error, :code_already_used}
        else
          {:error, %Ash.Error.Invalid{errors: errors}}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  defp current_code_timestamp(period) do
    now = System.system_time(:second)
    div(now, period) * period
  end

  defp maybe_generate_token(record, _strategy, opts) do
    record = add_authentication_metadata(record)

    if Info.authentication_tokens_enabled?(record.__struct__) do
      {:ok, token, _claims} = Jwt.token_for_user(record, %{}, opts)
      Resource.put_metadata(record, :token, token)
    else
      record
    end
  end

  defp add_authentication_metadata(record) do
    existing_strategies = get_existing_strategies(record)
    strategies = Enum.uniq(existing_strategies ++ [:totp])

    record
    |> Resource.put_metadata(:authentication_strategies, strategies)
    |> Resource.put_metadata(:totp_verified_at, DateTime.utc_now())
  end

  defp get_existing_strategies(record) do
    case record.__metadata__ do
      %{authentication_strategies: strategies} when is_list(strategies) -> strategies
      _ -> []
    end
  end
end
