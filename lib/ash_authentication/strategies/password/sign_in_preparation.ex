# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.SignInPreparation do
  @moduledoc """
  Prepare a query for sign in

  This preparation performs two jobs, one before the query executes and one
  after.

  Firstly, it constrains the query to match the identity field passed to the
  action.

  Secondly, it validates the supplied password using the configured hash
  provider, and if correct allows the record to be returned, otherwise returns
  an authentication failed error.
  """
  use Ash.Resource.Preparation
  alias Ash.{Error.Unknown, Query, Resource.Preparation}
  alias AshAuthentication.{Errors.AuthenticationFailed, Errors.UnconfirmedUser, Info, Jwt}
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, options, context) do
    {:ok, strategy} = Info.find_strategy(query, context, options)
    identity_field = strategy.identity_field
    hashed_password_field = strategy.hashed_password_field
    identity = Query.get_argument(query, identity_field)

    query =
      if is_nil(identity) do
        # This will fail due to the argument being `nil`, so this is just a formality
        Query.filter(query, false)
      else
        query
        |> Query.filter(^ref(identity_field) == ^identity)
        |> Query.filter(not is_nil(^ref(hashed_password_field)))
      end

    query
    |> check_sign_in_token_configuration(strategy)
    |> Query.before_action(fn query ->
      Ash.Query.ensure_selected(query, [strategy.hashed_password_field])
    end)
    |> Query.after_action(fn
      query, [record] when is_binary(:erlang.map_get(strategy.hashed_password_field, record)) ->
        password = Query.get_argument(query, strategy.password_field)

        check_password_and_confirmation(strategy, password, record, query, context)

      query, [] ->
        strategy.hash_provider.simulate()

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
        strategy.hash_provider.simulate()

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

  defp check_password_and_confirmation(strategy, password, record, query, context) do
    with :ok <- validate_password(strategy, password, record),
         :ok <- validate_user_confirmed(strategy, record, query) do
      token_type = query.context[:token_type] || :user
      extra_claims = query.context[:extra_token_claims] || %{}

      case maybe_generate_token(
             token_type,
             record,
             strategy,
             extra_claims,
             Ash.Context.to_opts(context)
           ) do
        {:ok, record} -> {:ok, [record]}
        {:error, error} -> {:error, error}
      end
    end
  end

  defp validate_password(strategy, password, record) do
    if strategy.hash_provider.valid?(password, Map.get(record, strategy.hashed_password_field)) do
      :ok
    else
      {:error,
       AuthenticationFailed.exception(
         strategy: strategy,
         caused_by: %{
           module: __MODULE__,
           action: :sign_in,
           message: "Password is not valid"
         }
       )}
    end
  end

  defp validate_user_confirmed(strategy, record, query) do
    if user_confirmed_if_needed(record, strategy) do
      :ok
    else
      {:error,
       AuthenticationFailed.exception(
         strategy: strategy,
         query: query,
         caused_by:
           UnconfirmedUser.exception(
             resource: query.resource,
             field: strategy.identity_field,
             confirmation_field: strategy.require_confirmed_with
           )
       )}
    end
  end

  defp check_sign_in_token_configuration(query, strategy)
       when query.context.token_type == :sign_in and not strategy.sign_in_tokens_enabled? do
    Query.add_error(
      query,
      Unknown.exception(
        message: """
        Invalid configuration detected. A sign in token was requested for the #{strategy.name} strategy on #{inspect(query.resource)}, but that strategy
        does not support sign in tokens. See `sign_in_tokens_enabled?` for more.
        """
      )
    )
  end

  defp check_sign_in_token_configuration(query, _) do
    query
  end

  defp maybe_generate_token(purpose, record, strategy, extra_claims, opts)
       when purpose in [:user, :sign_in] do
    if AshAuthentication.Info.authentication_tokens_enabled?(record.__struct__) do
      generate_token(purpose, record, strategy, extra_claims, opts)
    else
      maybe_add_authentication_metadata(purpose, record)
    end
  end

  defp generate_token(:sign_in, record, strategy, extra_claims, opts)
       when strategy.sign_in_tokens_enabled? do
    # Sign-in tokens are intermediate tokens (e.g., for sign-in links)
    # Don't add authentication_strategies metadata since auth isn't complete
    claims = Map.put(extra_claims, "purpose", "sign_in")

    case Jwt.token_for_user(
           record,
           claims,
           Keyword.merge(opts,
             token_lifetime: strategy.sign_in_token_lifetime,
             purpose: :sign_in
           )
         ) do
      {:ok, token, _claims} ->
        {:ok, Ash.Resource.put_metadata(record, :token, token)}

      {:error, error} ->
        {:error, error}
    end
  end

  defp generate_token(purpose, record, _strategy, extra_claims, opts) do
    # Full authentication - add metadata tracking
    record = add_authentication_metadata(record)
    claims = Map.put(extra_claims, "purpose", to_string(purpose))

    case Jwt.token_for_user(record, claims, opts) do
      {:ok, token, _claims} ->
        {:ok, Ash.Resource.put_metadata(record, :token, token)}

      {:error, error} ->
        {:error, error}
    end
  end

  defp maybe_add_authentication_metadata(:user, record) do
    add_authentication_metadata(record)
  end

  defp maybe_add_authentication_metadata(_purpose, record) do
    record
  end

  defp add_authentication_metadata(record) do
    existing_strategies = get_existing_strategies(record)
    strategies = Enum.uniq(existing_strategies ++ [:password])

    Ash.Resource.put_metadata(record, :authentication_strategies, strategies)
  end

  defp get_existing_strategies(record) do
    case record.__metadata__ do
      %{authentication_strategies: strategies} when is_list(strategies) -> strategies
      _ -> []
    end
  end

  def user_confirmed_if_needed(_user, %{require_confirmed_with: nil} = _strategy), do: true

  def user_confirmed_if_needed(user, %{require_confirmed_with: field} = _strategy),
    do: Map.get(user, field) != nil
end
