# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.Plug do
  @moduledoc """
  Plugs for the TOTP strategy.

  Handles setup and sign-in for TOTP authentication.
  """

  alias AshAuthentication.{Info, Strategy, Strategy.Totp}
  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  @doc "Handle a TOTP setup request"
  @spec setup(Conn.t(), Totp.t()) :: Conn.t()
  def setup(conn, strategy) do
    params = %{user: get_actor(conn)}
    opts = opts(conn)
    result = Strategy.action(strategy, :setup, params, opts)
    store_authentication_result(conn, result)
  end

  @doc "Handle a TOTP confirm setup request"
  @spec confirm_setup(Conn.t(), Totp.t()) :: Conn.t()
  def confirm_setup(conn, strategy) do
    params = Map.merge(%{user: get_actor(conn)}, subject_params(conn, strategy))
    opts = opts(conn)
    result = Strategy.action(strategy, :confirm_setup, params, opts)
    store_authentication_result(conn, result)
  end

  @doc "Handle a TOTP sign-in request"
  @spec sign_in(Conn.t(), Totp.t()) :: Conn.t()
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
    [actor: get_actor(conn), tenant: get_tenant(conn), context: get_context(conn)]
    |> Enum.reject(&is_nil(elem(&1, 1)))
  end
end
