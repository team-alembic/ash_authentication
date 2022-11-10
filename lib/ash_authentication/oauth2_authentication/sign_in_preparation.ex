defmodule AshAuthentication.OAuth2Authentication.SignInPreparation do
  @moduledoc """
  Prepare a query for sign in

  Performs three main tasks:

    1. Ensures that there is only one matching user record returned, otherwise
       returns an authentication failed error.
    2. Generates an access token if token generation is enabled.
    3. Updates the user identity resource, if one is enabled.
  """
  use Ash.Resource.Preparation
  alias AshAuthentication.OAuth2Authentication, as: OAuth2
  alias AshAuthentication.{Errors.AuthenticationFailed, Jwt, ProviderIdentity}
  alias Ash.{Query, Resource.Preparation}
  require Ash.Query
  import AshAuthentication.Utils, only: [is_falsy: 1]

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.context()) :: Query.t()
  def prepare(query, _opts, _context) do
    query
    |> Query.after_action(fn
      query, [user] ->
        with {:ok, user} <- maybe_update_identity(user, query) do
          {:ok, [maybe_generate_token(user)]}
        end

      _, _ ->
        {:error, AuthenticationFailed.exception(query: query)}
    end)
  end

  defp maybe_update_identity(user, query) do
    case OAuth2.Info.identity_resource(query.resource) do
      {:ok, falsy} when is_falsy(falsy) ->
        user

      :error ->
        user

      {:ok, resource} ->
        identity_relationship = OAuth2.Info.identity_relationship_name!(query.resource)

        resource
        |> ProviderIdentity.Actions.upsert(%{
          user_info: Query.get_argument(query, :user_info),
          oauth_tokens: Query.get_argument(query, :oauth_tokens),
          provider: OAuth2.Info.provider_name!(query.resource),
          user_id: user.id
        })
        |> case do
          {:ok, _identity} ->
            user
            |> query.api.load(identity_relationship)

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp maybe_generate_token(user) do
    if AshAuthentication.Info.tokens_enabled?(user.__struct__) do
      {:ok, token, _claims} = Jwt.token_for_record(user)
      %{user | __metadata__: Map.put(user.__metadata__, :token, token)}
    else
      user
    end
  end
end
