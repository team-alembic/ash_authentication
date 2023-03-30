defmodule AshAuthentication.Strategy.Password.Plug do
  @moduledoc """
  Plugs for the password strategy.

  Handles registration, sign-in and password resets.
  """

  alias Ash.Resource
  alias AshAuthentication.{Info, Jwt, Strategy, Strategy.Password}
  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  @doc "Handle a registration request"
  @spec register(Conn.t(), Password.t()) :: Conn.t()
  def register(conn, strategy) do
    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :register, params, opts)
    store_authentication_result(conn, result)
  end

  @doc "Handle a sign-in request"
  @spec sign_in(Conn.t(), Password.t()) :: Conn.t()
  def sign_in(conn, strategy) do
    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :sign_in, params, opts)
    store_authentication_result(conn, result)
  end

  @doc "Handle a request to validate a sign in token"
  @spec validate_sign_in_token(Conn.t(), Password.t()) :: Conn.t()
  def validate_sign_in_token(conn, strategy) do
    params = conn.params
    opts = opts(conn)

    result =
      with {:ok, %{"sub" => sub} = claims, _} <- Jwt.verify(params["token"], strategy.resource),
           :ok <- verify_sign_in_token_purpose(claims),
           {:ok, user} <-
             AshAuthentication.subject_to_user(
               sub,
               strategy.resource,
               Keyword.put(opts, :tenant, claims["tenant"] || opts[:tenant])
             ),
           {:ok, token, _claims} <- Jwt.token_for_user(user) do
        {:ok, Resource.put_metadata(user, :token, token)}
      else
        _ ->
          {:error, :invalid_sign_in_token}
      end

    store_authentication_result(conn, result)
  end

  @doc "Handle a reset request request"
  @spec reset_request(Conn.t(), Password.t()) :: Conn.t()
  def reset_request(conn, strategy) do
    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :reset_request, params, opts)
    store_authentication_result(conn, result)
  end

  @doc "Handle a reset request"
  @spec reset(Conn.t(), Password.t()) :: Conn.t()
  def reset(conn, strategy) do
    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :reset, params, opts)
    store_authentication_result(conn, result)
  end

  defp subject_params(conn, strategy) do
    subject_name =
      strategy.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    Map.get(conn.params, subject_name, %{})
  end

  defp opts(conn) do
    [actor: get_actor(conn), tenant: get_tenant(conn)]
    |> Enum.reject(&is_nil(elem(&1, 1)))
  end

  defp verify_sign_in_token_purpose(%{"purpose" => "sign_in"}), do: :ok
  defp verify_sign_in_token_purpose(_), do: :error
end
