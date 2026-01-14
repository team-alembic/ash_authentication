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

  @doc """
  Handle a TOTP verification request for step-up authentication.

  This is used when an already-authenticated user needs to verify their TOTP
  code to access protected resources. The user is obtained from the connection's
  actor (set by authentication middleware).

  On success, stores the verification result and marks TOTP as verified in the
  user's metadata.
  """
  @spec verify(Conn.t(), Totp.t()) :: Conn.t()
  def verify(conn, strategy) do
    user = get_actor(conn)
    params = subject_params(conn, strategy) |> Map.put("user", user)
    opts = opts(conn)
    result = Strategy.action(strategy, :verify, params, opts)

    case result do
      {:ok, true} ->
        # Verification succeeded - update user metadata and store success
        user_with_metadata =
          user
          |> Ash.Resource.put_metadata(:totp_verified_at, DateTime.utc_now())

        store_authentication_result(conn, {:ok, user_with_metadata})

      {:ok, false} ->
        store_authentication_result(conn, {:error, "Invalid TOTP code"})

      error ->
        store_authentication_result(conn, error)
    end
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
