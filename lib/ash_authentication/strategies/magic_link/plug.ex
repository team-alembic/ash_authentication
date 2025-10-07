# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.MagicLink.Plug do
  @moduledoc """
  Plugs for the magic link strategy.

  Handles requests and sign-ins.
  """

  alias AshAuthentication.{Info, Strategy, Strategy.MagicLink}
  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]
  require EEx

  @doc """
  Handle a request for a magic link.

  Retrieves form parameters from nested within the subject name, eg:

  ```
  %{
    "user" => %{
      "email" => "marty@mcfly.me"
    }
  }
  ```
  """
  @spec request(Conn.t(), MagicLink.t()) :: Conn.t()
  def request(conn, strategy) do
    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :request, params, opts)
    store_authentication_result(conn, result)
  end

  @doc """
  Present a sign in button to the user.
  """
  @spec accept(Conn.t(), MagicLink.t()) :: Conn.t()
  # sobelow_skip ["XSS.SendResp"]
  def accept(conn, strategy) do
    subject_params = subject_params(conn, strategy)
    param_name = to_string(strategy.token_param_name)
    token = Map.get(conn.params, param_name, subject_params[param_name])

    conn
    |> Conn.put_resp_content_type("text/html")
    |> Conn.send_resp(200, render_form(strategy: strategy, conn: conn, token: token))
  end

  EEx.function_from_file(:defp, :render_form, Path.join(__DIR__, "sign_in_form.html.eex"), [
    :assigns
  ])

  @doc """
  Sign in via magic link.
  """
  @spec sign_in(Conn.t(), MagicLink.t()) :: Conn.t()
  def sign_in(conn, strategy) do
    param_name =
      strategy.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    params =
      case Map.fetch(conn.params, param_name) do
        :error -> conn.params
        {:ok, params} -> params
      end

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
