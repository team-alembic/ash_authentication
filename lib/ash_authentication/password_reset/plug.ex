defmodule AshAuthentication.PasswordReset.Plug do
  @moduledoc """
  Handlers for incoming HTTP requests.
  """

  import AshAuthentication.Plug.Helpers, only: [private_store: 2]
  alias AshAuthentication.PasswordReset
  alias Plug.Conn

  @doc """
  Handle an inbound password reset request.
  """
  @spec request(Conn.t(), any) :: Conn.t()
  def request(%{params: params, private: %{authenticator: config}} = conn, _opts) do
    params =
      params
      |> Map.get(to_string(config.subject_name), %{})

    case PasswordReset.request_password_reset(config.resource, params) do
      {:ok, _} ->
        private_store(conn, {:success, nil})

      {:error, reason} ->
        private_store(conn, {:failure, reason})
    end
  end

  @doc """
  Handle an inbound password reset.
  """
  @spec callback(Conn.t(), any) :: Conn.t()
  def callback(%{params: params, private: %{authenticator: config}} = conn, _opts) do
    params =
      params
      |> Map.get(to_string(config.subject_name), %{})

    case PasswordReset.reset_password(config.resource, params) do
      {:ok, user} when is_struct(user, config.resource) ->
        private_store(conn, {:success, user})

      {:error, reason} ->
        private_store(conn, {:failure, reason})
    end
  end
end
