defmodule AshAuthentication.Strategy.OAuth2.SignInPreparation do
  @moduledoc """
  Prepare a query for sign in

  Performs three main tasks:

    1. Ensures that there is only one matching user record returned, otherwise
       returns an authentication failed error.
    2. Generates an access token if token generation is enabled.
    3. Updates the user identity resource, if one is enabled.
  """
  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt, UserIdentity}
  require Ash.Query
  import AshAuthentication.Utils, only: [is_falsy: 1]

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _opts, _context) do
    case Info.strategy_for_action(query.resource, query.action.name) do
      :error ->
        {:error,
         AuthenticationFailed.exception(
           strategy: :unknown,
           query: query,
           caused_by: %{
             module: __MODULE__,
             action: query.action,
             message: "Unable to infer strategy"
           }
         )}

      {:ok, strategy} ->
        query
        |> Query.after_action(fn
          query, [user] ->
            with {:ok, user} <- maybe_update_identity(user, query, strategy) do
              {:ok, [maybe_generate_token(user)]}
            end

          _, _ ->
            {:error,
             AuthenticationFailed.exception(
               strategy: strategy,
               query: query,
               caused_by: %{
                 module: __MODULE__,
                 action: query.action,
                 strategy: strategy,
                 message: "Query should return a single user"
               }
             )}
        end)
    end
  end

  defp maybe_update_identity(user, _query, strategy) when is_falsy(strategy.identity_resource),
    do: {:ok, user}

  defp maybe_update_identity(user, query, strategy) do
    strategy.identity_resource
    |> UserIdentity.Actions.upsert(%{
      user_info: Query.get_argument(query, :user_info),
      oauth_tokens: Query.get_argument(query, :oauth_tokens),
      strategy: strategy.name,
      user_id: user.id
    })
    |> case do
      {:ok, _identity} ->
        user
        |> Ash.load(strategy.identity_relationship_name, domain: Info.domain!(strategy.resource))

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_generate_token(user) do
    if AshAuthentication.Info.authentication_tokens_enabled?(user.__struct__) do
      {:ok, token, _claims} = Jwt.token_for_user(user)
      %{user | __metadata__: Map.put(user.__metadata__, :token, token)}
    else
      user
    end
  end
end
