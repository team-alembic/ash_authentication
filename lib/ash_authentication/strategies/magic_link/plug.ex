defmodule AshAuthentication.Strategy.MagicLink.Plug do
  @moduledoc """
  Plugs for the magic link strategy.

  Handles requests and sign-ins.
  """

  alias AshAuthentication.{Info, Strategy, Strategy.MagicLink}
  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

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
  Sign in via magic link.
  """
  @spec sign_in(Conn.t(), MagicLink.t()) :: Conn.t()
  def sign_in(conn, strategy) do
    params =
      conn.params
      |> Map.take([to_string(strategy.token_param_name)])

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
    [actor: get_actor(conn), tenant: get_tenant(conn)]
    |> Enum.reject(&is_nil(elem(&1, 1)))
  end
end
