# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule ExampleMultiTenant.AuthPlug do
  @moduledoc false
  use AshAuthentication.Plug, otp_app: :ash_authentication

  @impl true

  def handle_success(conn, {strategy, phase}, nil, nil) do
    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      200,
      Jason.encode!(%{status: :success, strategy: strategy, phase: phase})
    )
  end

  def handle_success(conn, {strategy, phase}, user, token) do
    conn
    |> store_in_session(user)
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      200,
      Jason.encode!(%{
        status: :success,
        token: token,
        user: Map.take(user, ~w[username id email]a),
        strategy: strategy,
        phase: phase
      })
    )
  end

  @impl true
  def handle_failure(conn, {strategy, phase}, reason) do
    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      401,
      Jason.encode!(%{
        status: :failure,
        reason: inspect(reason),
        strategy: strategy,
        phase: phase
      })
    )
  end
end
