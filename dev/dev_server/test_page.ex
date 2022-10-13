defmodule DevServer.TestPage do
  @moduledoc """
  Displays a very basic login form according to the currently configured
  Überauth providers.
  """
  @behaviour Plug
  alias Plug.Conn
  require EEx

  EEx.function_from_file(:defp, :render, String.replace(__ENV__.file, ".ex", ".html.eex"), [
    :assigns
  ])

  @doc false
  @impl true
  @spec init(keyword) :: keyword
  def init(opts), do: opts

  @doc false
  @spec call(Conn.t(), any) :: Conn.t()
  @impl true
  def call(conn, _opts) do
    resources = AshAuthentication.authenticated_resources(:ash_authentication)

    current_actors =
      conn.assigns
      |> Stream.filter(fn {key, _value} ->
        key
        |> to_string()
        |> String.starts_with?("current_")
      end)
      |> Map.new()

    payload = render(resources: resources, current_actors: current_actors)
    Conn.send_resp(conn, 200, payload)
  end
end
