defmodule AshAuthentication.Strategy.OAuth2.Plug do
  @moduledoc """
  Handlers for incoming OAuth2 HTTP requests.
  """

  alias Ash.Error.Framework.AssumptionFailed
  alias AshAuthentication.{Errors, Info, Strategy, Strategy.OAuth2}
  alias Assent.{Config, HTTPAdapter.Finch}
  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]
  import Plug.Conn

  @raw_config_attrs [
    :auth_method,
    :authorization_params,
    :client_authentication_method,
    :id_token_signed_response_alg,
    :id_token_ttl_seconds,
    :openid_configuration_uri
  ]

  @doc """
  Perform the request phase of OAuth2.

  Builds a redirection URL based on the provider configuration and redirects the
  user to that endpoint.
  """
  @spec request(Conn.t(), OAuth2.t()) :: Conn.t()
  # sobelow_skip ["XSS.SendResp"]
  def request(conn, strategy) do
    with {:ok, config} <- config_for(strategy),
         {:ok, config} <- maybe_add_nonce(config, strategy),
         {:ok, session_key} <- session_key(strategy),
         {:ok, %{session_params: session_params, url: url}} <-
           strategy.assent_strategy.authorize_url(config) do
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
         {:ok, %{user: user, token: token}} <-
           strategy.assent_strategy.callback(config, conn.params),
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
    [actor: get_actor(conn), tenant: get_tenant(conn), context: get_context(conn) || %{}]
    |> Enum.reject(&is_nil(elem(&1, 1)))
  end

  defp config_for(strategy) do
    config =
      strategy
      |> Map.take(@raw_config_attrs)

    with {:ok, config} <- add_secret_value(config, strategy, :base_url),
         {:ok, config} <- add_secret_value(config, strategy, :authorize_url, !!strategy.base_url),
         {:ok, config} <- add_secret_value(config, strategy, :client_id, !!strategy.base_url),
         {:ok, config} <- add_secret_value(config, strategy, :client_secret, !!strategy.base_url),
         {:ok, config} <- add_secret_value(config, strategy, :token_url, !!strategy.base_url),
         {:ok, config} <-
           add_secret_value(
             config,
             strategy,
             :team_id,
             strategy.assent_strategy != Assent.Strategy.Apple
           ),
         {:ok, config} <-
           add_secret_value(
             config,
             strategy,
             :private_key_id,
             strategy.assent_strategy != Assent.Strategy.Apple
           ),
         {:ok, config} <-
           add_secret_value(
             config,
             strategy,
             :private_key_path,
             strategy.assent_strategy != Assent.Strategy.Apple
           ),
         {:ok, config} <-
           add_secret_value(config, strategy, :trusted_audiences, true),
         {:ok, config} <- add_http_adapter(config),
         {:ok, config} <-
           add_secret_value(
             config,
             strategy,
             :user_url,
             !!strategy.authorize_url || !!strategy.base_url
           ),
         {:ok, redirect_uri} <- build_redirect_uri(strategy),
         {:ok, jwt_algorithm} <-
           Info.authentication_tokens_signing_algorithm(strategy.resource) do
      config =
        config
        |> Map.put(:jwt_algorithm, jwt_algorithm)
        |> Map.put(:redirect_uri, redirect_uri)
        |> Map.update(:client_authentication_method, nil, &to_string/1)
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

  # With OpenID Connect we can pass a "nonce" value into the assent strategy
  # which is an additional way to ensure that the callback matches the request.
  defp maybe_add_nonce(config, strategy) do
    case fetch_secret(strategy, :nonce) do
      {:ok, value} when is_binary(value) and byte_size(value) > 0 ->
        {:ok, Keyword.put(config, :nonce, value)}

      {:ok, false} ->
        {:ok, config}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp add_secret_value(config, strategy, secret_name, allow_nil? \\ false) do
    case fetch_secret(strategy, secret_name) do
      {:ok, nil} when allow_nil? ->
        {:ok, config}

      {:ok, nil} ->
        path = [:authentication, :strategies, strategy.name, secret_name]
        {:error, Errors.MissingSecret.exception(path: path, resource: strategy.resource)}

      {:ok, value} when is_binary(value) and byte_size(value) > 0 ->
        {:ok, Map.put(config, secret_name, value)}

      {:ok, list} when is_list(list) ->
        {:ok, Map.put(config, secret_name, list)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_secret(strategy, secret_name) do
    path = [:authentication, :strategies, strategy.name, secret_name]

    with {:ok, {secret_module, secret_opts}} <- Map.fetch(strategy, secret_name),
         {:ok, secret} when is_binary(secret) and byte_size(secret) > 0 <-
           secret_module.secret_for(path, strategy.resource, secret_opts) do
      {:ok, secret}
    else
      {:ok, secret} ->
        {:ok, secret}

      _ ->
        {:error, Errors.MissingSecret.exception(path: path, resource: strategy.resource)}
    end
  end

  defp build_redirect_uri(strategy) do
    with {:ok, subject_name} <- Info.authentication_subject_name(strategy.resource),
         {:ok, redirect_uri} <- fetch_secret(strategy, :redirect_uri),
         {:ok, uri} <- URI.new(redirect_uri) do
      suffix = Path.join([to_string(subject_name), to_string(strategy.name), "callback"])
      # Don't append the path if the secret ends with the path already
      path =
        if String.ends_with?(uri.path, suffix) do
          uri.path
        else
          Path.join([uri.path || "/", suffix])
        end

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

  defp add_http_adapter(config) do
    http_adapter =
      Application.get_env(
        :ash_authentication,
        :http_adapter,
        {Finch, supervisor: AshAuthentication.Finch}
      )

    {:ok, Map.put(config, :http_adapter, http_adapter)}
  end
end
