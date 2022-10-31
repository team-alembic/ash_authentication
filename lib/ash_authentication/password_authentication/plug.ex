defmodule AshAuthentication.PasswordAuthentication.Plug do
  @moduledoc """
  Handlers for incoming request and callback HTTP requests.

  AshAuthentication is written with an eye towards OAuth which uses a two-phase
  request/callback process which can be used to register and sign in an user in
  a single flow.  This doesn't really work that well with `PasswordAuthentication` which has
  seperate "registration" and "sign-in" actions.

  Here we simply ignore the request phase, which will cause an error to be
  returned to the remote user if they somehow find themselves there.

  We use the "callback" phase to handle both registration and sign in by passing
  an "action" parameter along with the form data.
  """
  import AshAuthentication.Plug.Helpers, only: [private_store: 2]
  alias AshAuthentication.PasswordAuthentication
  alias Plug.Conn

  @doc """
  Handle the request phase.

  The password authentication provider does nothing with the request phase, and just returns
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
      {:ok, user} when is_struct(user, config.resource) ->
        private_store(conn, {:success, user})

      {:error, changeset} ->
        private_store(conn, {:failure, changeset})
    end
  end

  def callback(conn, _opts), do: conn

  defp do_action(%{"action" => "sign_in"} = attrs, resource),
    do: PasswordAuthentication.sign_in_action(resource, attrs)

  defp do_action(%{"action" => "register"} = attrs, resource),
    do: PasswordAuthentication.register_action(resource, attrs)
end
