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
  alias Ash.{Query, Resource.Preparation}
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.context()) :: Query.t()
  def prepare(query, _opts, _context) do
    strategy = Info.strategy_for_action!(query.resource, query.action.name)
    identity_field = strategy.identity_field
    identity = Query.get_argument(query, identity_field)

    query
    |> Query.filter(ref(^identity_field) == ^identity)
    |> Query.after_action(fn
      query, [record] ->
        password = Query.get_argument(query, strategy.password_field)

        if strategy.hash_provider.valid?(password, record.hashed_password),
          do: {:ok, [maybe_generate_token(record)]},
          else: auth_failed(query)

      _, _ ->
        strategy.hash_provider.simulate()
        auth_failed(query)
    end)
  end

  defp auth_failed(query), do: {:error, AuthenticationFailed.exception(query: query)}

  defp maybe_generate_token(record) do
    if AshAuthentication.Info.authentication_tokens_enabled?(record.__struct__) do
      {:ok, token, _claims} = Jwt.token_for_user(record)
      %{record | __metadata__: Map.put(record.__metadata__, :token, token)}
    else
      record
    end
  end
end
