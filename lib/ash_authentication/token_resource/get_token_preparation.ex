defmodule AshAuthentication.TokenResource.GetTokenPreparation do
  @moduledoc """
  Constrains a query to only records which match the `jti` or `token` argument
  and optionally by the `purpose` argument.
  """

  use Ash.Resource.Preparation
  alias Ash.{Error.Query.InvalidArgument, Query, Resource.Preparation}
  alias AshAuthentication.Jwt
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _, _) do
    jti = get_jti(query)
    purpose = Query.get_argument(query, :purpose)

    query
    |> Query.filter(jti: jti)
    |> then(fn query ->
      if purpose, do: Query.filter(query, purpose: purpose), else: query
    end)
    |> Query.filter(expires_at > now())
  end

  defp get_jti(query),
    do: get_jti(Query.get_argument(query, :jti), Query.get_argument(query, :token))

  defp get_jti(jti, _token) when byte_size(jti) > 0, do: jti

  defp get_jti(_jti, token) when byte_size(token) > 0 do
    token
    |> Jwt.peek()
    |> case do
      {:ok, %{"jti" => jti}} -> jti
      _ -> get_jti(nil, nil)
    end
  end

  defp get_jti(_jti, _token),
    do:
      raise(
        InvalidArgument.exception(
          field: :jti,
          message: "At least one of `jti` or `token` arguments must be present"
        )
      )
end
