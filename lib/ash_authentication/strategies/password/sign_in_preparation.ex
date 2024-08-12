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
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt}
  alias Ash.{Error.Unknown, Query, Resource.Preparation}
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, options, context) do
    {:ok, strategy} = Info.find_strategy(query, context, options)
    identity_field = strategy.identity_field
    identity = Query.get_argument(query, identity_field)

    query =
      if is_nil(identity) do
        # This will fail due to the argument being `nil`, so this is just a formality
        Query.filter(query, false)
      else
        Query.filter(query, ^ref(identity_field) == ^identity)
      end

    query
    |> check_sign_in_token_configuration(strategy)
    |> Query.before_action(fn query ->
      Ash.Query.ensure_selected(query, [strategy.hashed_password_field])
    end)
    |> Query.after_action(fn
      query, [record] when is_binary(:erlang.map_get(strategy.hashed_password_field, record)) ->
        password = Query.get_argument(query, strategy.password_field)

        if strategy.hash_provider.valid?(
             password,
             Map.get(record, strategy.hashed_password_field)
           ) do
          token_type = query.context[:token_type] || :user

          {:ok, [maybe_generate_token(token_type, record, strategy)]}
        else
          {:error,
           AuthenticationFailed.exception(
             strategy: strategy,
             query: query,
             caused_by: %{
               module: __MODULE__,
               action: query.action,
               resource: query.resource,
               message: "Password is not valid"
             }
           )}
        end

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

  defp maybe_generate_token(purpose, record, strategy) when purpose in [:user, :sign_in] do
    if AshAuthentication.Info.authentication_tokens_enabled?(record.__struct__) do
      generate_token(purpose, record, strategy)
    else
      record
    end
  end

  defp generate_token(:sign_in, record, strategy) when strategy.sign_in_tokens_enabled? do
    {:ok, token, _claims} =
      Jwt.token_for_user(record, %{"purpose" => "sign_in"},
        token_lifetime: strategy.sign_in_token_lifetime,
        purpose: :sign_in
      )

    Ash.Resource.put_metadata(record, :token, token)
  end

  defp generate_token(purpose, record, _strategy) do
    {:ok, token, _claims} = Jwt.token_for_user(record, %{"purpose" => to_string(purpose)})

    Ash.Resource.put_metadata(record, :token, token)
  end
end
