# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.Plug do
  @moduledoc """
  Plugs for the OTP strategy.

  Handles request and sign-in phases.
  """

  alias AshAuthentication.{Info, Strategy, Strategy.Otp}
  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  @doc """
  Handle a request for an OTP code.

  Retrieves form parameters from nested within the subject name, eg:

  ```
  %{
    "user" => %{
      "email" => "marty@mcfly.me"
    }
  }
  ```
  """
  @spec request(Conn.t(), Otp.t()) :: Conn.t()
  def request(conn, strategy) do
    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :request, params, opts)
    store_authentication_result(conn, result)
  end

  @doc """
  Sign in via OTP code.
  """
  @spec sign_in(Conn.t(), Otp.t()) :: Conn.t()
  def sign_in(conn, strategy) do
    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :sign_in, params, opts)
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
    [actor: get_actor(conn), tenant: get_tenant(conn), context: get_context(conn) || %{}]
    |> Enum.reject(&is_nil(elem(&1, 1)))
  end
end
