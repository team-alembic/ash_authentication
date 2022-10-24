defmodule AshAuthentication.PasswordAuthentication.SignInPreparation do
  @moduledoc """
  Prepare a query for sign in

  This preparation performs two jobs, one before the query executes and one
  after.

  Firstly, it constrains the query to match the identity field pased on the
  identity argument passed to the action.

  Secondly, it validates the supplied password using the configured hash
  provider, and if correct allows the record to be returned, otherwise
  returns an empty result.
  """
  use Ash.Resource.Preparation
  alias AshAuthentication.{Errors.AuthenticationFailed, Jwt, PasswordAuthentication.Info}
  alias Ash.{Query, Resource.Preparation}
  require Ash.Query

  @impl true
  @spec prepare(Query.t(), keyword, Preparation.context()) :: Query.t()
  def prepare(query, _opts, _) do
    {:ok, identity_field} = Info.identity_field(query.resource)
    {:ok, password_field} = Info.password_field(query.resource)
    {:ok, hasher} = Info.hash_provider(query.resource)

    identity = Query.get_argument(query, identity_field)

    query
    |> Query.filter(ref(^identity_field) == ^identity)
    |> Query.after_action(fn
      query, [record] ->
        password = Query.get_argument(query, password_field)

        if hasher.valid?(password, record.hashed_password),
          do: {:ok, [maybe_generate_token(record)]},
          else: auth_failed(query)

      _, _ ->
        hasher.simulate()
        auth_failed(query)
    end)
  end

  defp auth_failed(query), do: {:error, AuthenticationFailed.exception(query: query)}

  defp maybe_generate_token(record) do
    if AshAuthentication.Info.tokens_enabled?(record.__struct__) do
      {:ok, token, _claims} = Jwt.token_for_record(record)
      %{record | __metadata__: Map.put(record.__metadata__, :token, token)}
    else
      record
    end
  end
end
