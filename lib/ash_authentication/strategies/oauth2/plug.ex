defmodule AshAuthentication.Strategy.OAuth2.Plug do
  @moduledoc """
  Handlers for incoming OAuth2 HTTP requests.
  """

  alias Ash.Error.Framework.AssumptionFailed
  alias AshAuthentication.{Errors, Info, Strategy, Strategy.OAuth2}
  alias Assent.{Config, HTTPAdapter.Mint}
  alias Assent.Strategy.OAuth2, as: Assent
  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]
  import Plug.Conn

  @doc """
  Perform the request phase of OAuth2.

  Builds a redirection URL based on the provider configuration and redirects the
  user to that endpoint.
  """
  @spec request(Conn.t(), OAuth2.t()) :: Conn.t()
  def request(conn, strategy) do
    with {:ok, config} <- config_for(strategy),
         {:ok, session_key} <- session_key(strategy),
         {:ok, %{session_params: session_params, url: url}} <- Assent.authorize_url(config) do
      conn
      |> put_session(session_key, session_params)
      |> put_resp_header("location", url)
      |> send_resp(:found, "Redirecting to #{strategy.name}")
    else
      {:error, reason} -> store_authentication_result(conn, {:error, reason})
    end
  end

  @doc """
  Perform the callback phase of OAuth2.

  Responds to a user being redirected back from the remote authentication
  provider, and validates the passed options, ultimately registering or
  signing-in a user if the authentication was successful.
  """
  @spec callback(Conn.t(), OAuth2.t()) :: Conn.t()
  def callback(conn, strategy) do
    with {:ok, session_key} <- session_key(strategy),
         {:ok, config} <- config_for(strategy),
         session_params when is_map(session_params) <- get_session(conn, session_key),
         conn <- delete_session(conn, session_key),
         config <- Config.put(config, :session_params, session_params),
         {:ok, %{user: user, token: token}} <- Assent.callback(config, conn.params),
         action_opts <- action_opts(conn),
         {:ok, user} <-
           register_or_sign_in_user(
             strategy,
             %{user_info: user, oauth_tokens: token},
             action_opts
           ) do
      store_authentication_result(conn, {:ok, user})
    else
      nil -> store_authentication_result(conn, {:error, nil})
      {:error, reason} -> store_authentication_result(conn, {:error, reason})
    end
  end

  defp action_opts(conn) do
    [actor: get_actor(conn), tenant: get_tenant(conn)]
    |> Enum.reject(&is_nil(elem(&1, 1)))
  end

  defp config_for(strategy) do
    with {:ok, client_id} <- fetch_secret(strategy, :client_id),
         {:ok, site} <- fetch_secret(strategy, :site),
         {:ok, redirect_uri} <- build_redirect_uri(strategy),
         {:ok, authorize_url} <- build_uri(strategy, :authorize_path),
         {:ok, token_url} <- build_uri(strategy, :token_path),
         {:ok, user_url} <- build_uri(strategy, :user_path) do
      config =
        [
          auth_method: strategy.auth_method,
          client_id: client_id,
          client_secret: get_secret(strategy, :client_secret),
          private_key: get_secret(strategy, :private_key),
          jwt_algorithm: Info.authentication_tokens_signing_algorithm(strategy.resource),
          authorization_params: strategy.authorization_params,
          redirect_uri: redirect_uri,
          site: site,
          authorize_url: authorize_url,
          token_url: token_url,
          user_url: user_url,
          http_adapter: Mint
        ]
        |> Enum.reject(&is_nil(elem(&1, 1)))

      {:ok, config}
    end
  end

  defp register_or_sign_in_user(strategy, params, opts) when strategy.registration_enabled?,
    do: Strategy.action(strategy, :register, params, opts)

  defp register_or_sign_in_user(strategy, params, opts),
    do: Strategy.action(strategy, :sign_in, params, opts)

  # We need to temporarily store some information about the request in the
  # session so that we can verify that there hasn't been a CSRF-related attack.
  defp session_key(strategy) do
    case Info.authentication_subject_name(strategy.resource) do
      {:ok, subject_name} ->
        {:ok, "#{subject_name}/#{strategy.name}"}

      :error ->
        {:error,
         AssumptionFailed.exception(
           message: "Resource `#{inspect(strategy.resource)}` has no subject name"
         )}
    end
  end

  defp fetch_secret(strategy, secret_name) do
    path = [:authentication, :strategies, strategy.name, secret_name]

    with {:ok, {secret_module, secret_opts}} <- Map.fetch(strategy, secret_name),
         {:ok, secret} when is_binary(secret) and byte_size(secret) > 0 <-
           secret_module.secret_for(path, strategy.resource, secret_opts) do
      {:ok, secret}
    else
      {:ok, secret} when is_binary(secret) -> {:ok, secret}
      _ -> {:error, Errors.MissingSecret.exception(path: path, resource: strategy.resource)}
    end
  end

  defp get_secret(strategy, secret_name) do
    case fetch_secret(strategy, secret_name) do
      {:ok, secret} -> secret
      _ -> nil
    end
  end

  defp build_redirect_uri(strategy) do
    with {:ok, subject_name} <- Info.authentication_subject_name(strategy.resource),
         {:ok, redirect_uri} <- fetch_secret(strategy, :redirect_uri),
         {:ok, uri} <- URI.new(redirect_uri) do
      path =
        Path.join([uri.path || "/", to_string(subject_name), to_string(strategy.name), "callback"])

      {:ok, to_string(%URI{uri | path: path})}
    else
      :error ->
        {:error,
         AssumptionFailed.exception(
           message: "Resource `#{inspect(strategy.resource)}` has no subject name"
         )}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_uri(strategy, secret_name) do
    with {:ok, site} <- fetch_secret(strategy, :site),
         {:ok, uri} <- URI.new(site),
         {:ok, path} <- fetch_secret(strategy, secret_name) do
      path = Path.join(uri.path || "/", path)

      {:ok, to_string(%URI{uri | path: path})}
    end
  end
end
