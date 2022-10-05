defmodule AshAuthentication.Identity.Plug do
  @moduledoc """
  FIXME
  """
  import Plug.Conn
  alias AshAuthentication.Identity
  alias Plug.Conn

  @doc """
  Handle the request phase.

  The identity provider does nothing with the request phase, and just returns
  the `conn` unmodified.
  """
  @spec request(Conn.t(), any) :: Conn.t()
  def request(conn, _opts), do: conn

  @doc """
  Handle the callback phase.

  Handles both sign-in and registration actions via the same endpoint.
  """
  @spec callback(Conn.t(), any) :: Conn.t()
  def callback(%{params: params, private: %{authenticator: config}} = conn, _opts) do
    params
    |> Map.get(to_string(config.subject_name), %{})
    |> do_action(config.resource)
    |> case do
      {:ok, actor} when is_struct(actor, config.resource) ->
        put_private(conn, :authentication_result, {:success, actor})

      _ ->
        conn
    end
  end

  def callback(conn, _opts), do: conn

  defp do_action(%{"action" => "sign_in"} = attrs, resource),
    do: Identity.sign_in_action(resource, attrs)

  defp do_action(%{"action" => "register"} = attrs, resource),
    do: Identity.register_action(resource, attrs)
end
