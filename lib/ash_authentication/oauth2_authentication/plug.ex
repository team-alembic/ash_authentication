defmodule AshAuthentication.OAuth2Authentication.Plug do
  @moduledoc """
  Handlers for incoming OAuth2 HTTP requests.
  """

  import AshAuthentication.Plug.Helpers, only: [private_store: 2]
  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.OAuth2Authentication, as: OAuth2
  alias Assent.Strategy.OAuth2, as: Strategy
  alias Plug.Conn
  import Plug.Conn
  require Logger

  @doc """
  Perform the request phase of OAuth2.

  Builds a redirection URL based on the provider configuration and redirects the
  user to that endpoint.
  """
  @spec request(Conn.t(), any) :: Conn.t()
  def request(conn, _opts) when is_map(conn.private.authenticator) do
    config = conn.private.authenticator

    with {:ok, provider_name} <- OAuth2.Info.provider_name(config.resource),
         {:ok, resource_config} <- OAuth2.Info.resource_config(config.resource),
         {:ok, %{session_params: session_params, url: url}} <-
           Strategy.authorize_url(resource_config) do
      conn
      |> put_session(session_key(config), session_params)
      |> put_resp_header("location", url)
      |> send_resp(:found, "Redirecting to #{provider_name}")
    else
      :error ->
        Logger.error(
          "Configuration error with OAuth2 configuration for `#{inspect(config.resource)}`"
        )

        conn

      {:error, reason} ->
        Logger.error(
          "Configuration error with OAuth2 configuration for `#{inspect(config.resource)}`: #{inspect(reason)}`"
        )

        conn
    end
  end

  @doc """
  Perform the callback phase of OAuth2.

  Responds to a user being redirected back from the remote authentication
  provider, and validates the passed options, ultimately registering or
  signing-in a user if the authentication was successful.
  """
  @spec callback(Conn.t(), any) :: Conn.t()
  def callback(conn, _opts) when is_map(conn.private.authenticator) do
    config = conn.private.authenticator

    with {:ok, resource_config} <- OAuth2.Info.resource_config(config.resource),
         session_key <- session_key(config),
         session_params when is_map(session_params) <- get_session(conn, session_key),
         conn <- delete_session(conn, session_key),
         resource_config <- Assent.Config.put(resource_config, :session_params, session_params),
         {:ok, %{user: user, token: token}} <- Strategy.callback(resource_config, conn.params),
         {:ok, user} <- register_or_sign_in_user(config, %{user_info: user, oauth_tokens: token}) do
      private_store(conn, {:success, user})
    else
      {:error, reason} -> private_store(conn, {:failure, reason})
      _ -> conn
    end
  end

  # We need to temporarily store some information about the request in the
  # session so that we can verify that there hasn't been a CSRF-related attack.
  defp session_key(config),
    do: "#{config.subject_name}/#{config.provider.provides(config.resource)}"

  defp register_or_sign_in_user(config, params) do
    registration_enabled? = OAuth2.Info.registration_enabled?(config.resource)
    sign_in_enabled? = OAuth2.Info.sign_in_enabled?(config.resource)

    cond do
      registration_enabled? ->
        OAuth2.register_action(config.resource, params)

      sign_in_enabled? ->
        OAuth2.sign_in_action(config.resource, params)

      true ->
        {:error, AuthenticationFailed.exception([])}
    end
  end
end
