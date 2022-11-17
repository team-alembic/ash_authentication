defmodule AshAuthentication.Strategy.Password.Plug do
  @moduledoc """
  Plugs for the password strategy.

  Handles registration, sign-in and password resets.
  """

  alias AshAuthentication.{Info, Strategy, Strategy.Password}
  alias Plug.Conn
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  @doc "Handle a registration request"
  @spec register(Conn.t(), Password.t()) :: Conn.t()
  def register(conn, strategy) do
    params =
      conn
      |> subject_params(strategy)

    result =
      strategy
      |> Strategy.action(:register, params)

    conn
    |> store_authentication_result(result)
  end

  @doc "Handle a sign-in request"
  @spec sign_in(Conn.t(), Password.t()) :: Conn.t()
  def sign_in(conn, strategy) do
    params =
      conn
      |> subject_params(strategy)

    result =
      strategy
      |> Strategy.action(:sign_in, params)

    conn
    |> store_authentication_result(result)
  end

  @doc "Handle a reset request request"
  @spec reset_request(Conn.t(), Password.t()) :: Conn.t()
  def reset_request(conn, strategy) do
    params =
      conn
      |> subject_params(strategy)

    result =
      strategy
      |> Strategy.action(:reset_request, params)

    conn
    |> store_authentication_result(result)
  end

  @doc "Handle a reset request"
  @spec reset(Conn.t(), Password.t()) :: Conn.t()
  def reset(conn, strategy) do
    params =
      conn
      |> subject_params(strategy)

    result =
      strategy
      |> Strategy.action(:reset, params)

    conn
    |> store_authentication_result(result)
  end

  defp subject_params(conn, strategy) do
    subject_name =
      strategy.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    Map.get(conn.params, subject_name, %{})
  end
end
