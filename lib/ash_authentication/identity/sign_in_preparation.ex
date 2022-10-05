defmodule AshAuthentication.Identity.SignInPreparation do
  @moduledoc """
  Prepare a query for sign in

  This preparation performs two jobs, one before the query executes and one
  after.

  Firstly, it constrains the query to match the identity field pased on the
  identity argument passed to the action.

  Secondly, it validates the supplied password using the configured hash
  provider, and if correct allows the user record to be returned, otherwise
  returns an empty result.
  """
  use Ash.Resource.Preparation
  alias AshAuthentication.{Errors.AuthenticationFailed, Identity.Config, JsonWebToken}
  alias Ash.{Query, Resource.Preparation}
  require Ash.Query

  @impl true
  @spec prepare(Query.t(), Keyword.t(), Preparation.context()) :: Query.t()
  def prepare(query, _opts, _) do
    {:ok, identity_field} = Config.identity_field(query.resource)
    {:ok, password_field} = Config.password_field(query.resource)
    {:ok, hasher} = Config.hash_provider(query.resource)

    identity = Query.get_argument(query, identity_field)

    query
    |> Query.filter(ref(^identity_field) == ^identity)
    |> Query.after_action(fn
      query, [user] ->
        password = Query.get_argument(query, password_field)

        if hasher.valid?(password, user.hashed_password),
          do: {:ok, [sign_in(user)]},
          else: auth_failed(query)

      _, _ ->
        hasher.simulate()
        auth_failed(query)
    end)
  end

  defp auth_failed(query), do: {:error, AuthenticationFailed.exception(query: query)}

  defp sign_in(user) do
    {:ok, token, _claims} = JsonWebToken.token_for_record(user)

    %{user | __metadata__: Map.put(user.__metadata__, :token, token)}
  end
end
