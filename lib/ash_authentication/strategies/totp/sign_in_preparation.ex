# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.SignInPreparation do
  @moduledoc """
  Preparation for the TOTP sign-in action.

  Verifies the TOTP code against the user's secret and generates a token
  on successful authentication.
  """
  use Ash.Resource.Preparation
  alias Ash.{Changeset, Query, Resource}
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt}

  @doc false
  @impl true
  def prepare(query, opts, context) do
    with {:ok, strategy} <- Info.find_strategy(query, context, opts),
         {:ok, identity} <- Query.fetch_argument(query, strategy.identity_field),
         {:ok, totp_code} <- Query.fetch_argument(query, :code) do
      identity_field = strategy.identity_field

      query =
        if is_nil(identity) do
          # This will fail due to the argument being `nil`, so this is just a formality
          Query.filter(query, false)
        else
          query
          |> Query.filter(^ref(identity_field) == ^identity)
          |> Query.filter(not is_nil(^ref(strategy.secret_field)))
        end

      query
      |> Query.before_action(fn query ->
        Query.ensure_selected(query, [strategy.secret_field, strategy.last_totp_at_field])
      end)
      |> Query.after_action(fn
        query, [record] when is_binary(:erlang.map_get(strategy.secret_field, record)) ->
          secret = Map.get(record, strategy.secret_field)
          last_totp_at = datetime_to_unix(Map.get(record, strategy.last_totp_at_field))

          if NimbleTOTP.valid?(secret, totp_code,
               since: last_totp_at,
               period: strategy.period
             ) do
            opts = Ash.Context.to_opts(context)

            with {:ok, record} <- update_last_totp_at(record, strategy, opts) do
              {:ok, [maybe_generate_token(record, strategy, opts)]}
            end
          else
            {:error,
             AuthenticationFailed.exception(
               strategy: strategy,
               query: query,
               caused_by: %{
                 module: __MODULE__,
                 strategy: strategy,
                 action: :sign_in,
                 message: "Invalid TOTP code"
               }
             )}
          end

        query, [] ->
          {:error,
           AuthenticationFailed.exception(
             strategy: strategy,
             query: query,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: :sign_in,
               message: "Query returned no users"
             }
           )}

        query, users when is_list(users) ->
          {:error,
           AuthenticationFailed.exception(
             strategy: strategy,
             query: query,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: :sign_in,
               message: "Query returned too many users"
             }
           )}
      end)
    end
  end

  defp update_last_totp_at(record, strategy, opts) do
    record
    |> Changeset.new()
    |> Changeset.set_context(%{private: %{ash_authentication?: true}})
    |> Changeset.for_update(:update, %{})
    |> Changeset.force_change_attribute(strategy.last_totp_at_field, DateTime.utc_now())
    |> Ash.update(opts)
  end

  defp maybe_generate_token(record, _strategy, opts) do
    if Info.authentication_tokens_enabled?(record.__struct__) do
      {:ok, token, _claims} = Jwt.token_for_user(record, %{}, opts)
      Resource.put_metadata(record, :token, token)
    else
      record
    end
  end

  defp datetime_to_unix(nil), do: 0
  defp datetime_to_unix(%DateTime{} = dt), do: DateTime.to_unix(dt)
  defp datetime_to_unix(unix) when is_integer(unix), do: unix
end
