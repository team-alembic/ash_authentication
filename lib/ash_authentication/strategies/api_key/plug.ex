# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.ApiKey.Plug do
  @moduledoc """
  Plug for authenticating using API keys.

  This plug validates API keys from either a query parameter or HTTP header.
  """

  @behaviour Plug

  alias Ash.PlugHelpers
  alias AshAuthentication.{Info, Strategy}
  alias Plug.Conn

  @type source_type :: :header | :query_param | :header_or_query_param
  @type auth_error :: :invalid_api_key | :missing_api_key | :authentication_failed

  @doc """
  Handles errors that occur during the api key authentication process.

  This function determines the response format based on the `Accept` header
  of the incoming request. If the client accepts JSON responses, it returns
  a JSON-formatted error message. Otherwise, it returns a plain text error
  message.

    - If the `Accept` header contains "json", the response will be:
      - Status: 401 Unauthorized
      - Content-Type: application/json
      - Body: `{"error":"Unauthorized"}`
    - Otherwise, the response will be:
      - Status: 401 Unauthorized
      - Content-Type: text/plain (default)
      - Body: `Unauthorized`
  """
  def on_error(conn, _error) do
    if Plug.Conn.get_req_header(conn, "accept") |> Enum.any?(&String.contains?(&1, "json")) do
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(401, ~s({"error":"Unauthorized"}))
      |> Plug.Conn.halt()
    else
      conn
      |> Plug.Conn.send_resp(401, "Unauthorized")
      |> Plug.Conn.halt()
    end
  end

  @doc """
  Initialize the plug with options.

  ## Options

  * `:resource` - The resource to authenticate against.
  * `:source` - Where to get the API key from. Can be `:header`, `:query_param` or `:header_or_query_param`. Default: `:header`.
    Keep in mind that query params are often stored in logs etc, so we *highly* recommend using `:header`.
  * `:param_name` - The name of the query parameter when `source: :query_param`. Default: `"api_key"`
  * `:header_prefix` - The prefix to strip from the Authorization header value when `source: :header`. Default: `"Bearer "`
  * `:strategy` - The name of the API key strategy being used, defaults to the only api key strategy on the resource, or an error if there are multiple.
  * `:required?` - If `true`, the absence of an API key is treated as an error, and the `on_error` function is called with `:missing_api_key`. Default: `true`.
  * `:on_error` - The function to call when an error occurs. Takes a `conn` and an `error` which will be `:invalid_api_key` or an AshAuthentication error. The default is: `AshAuthentication.Strategy.ApiKey.Plug.on_error/2`
  * `:assign` - The name of the assign to set the authenticated subject. Default: `:current_<subject>`, i.e `:current_user`
  """
  @impl true
  # sobelow_skip ["DOS.BinToAtom"]
  def init(opts) do
    resource = Keyword.fetch!(opts, :resource)
    required? = Keyword.get(opts, :required?, true)
    source = Keyword.get(opts, :source, :header)
    param_name = Keyword.get(opts, :param_name, "api_key")
    header_prefix = Keyword.get(opts, :header_prefix, "Bearer ")
    subject_name = AshAuthentication.Info.authentication_subject_name!(resource)
    assign = Keyword.get(opts, :assign, :"current_#{subject_name}")

    strategy =
      case Keyword.fetch(opts, :strategy) do
        {:ok, strategy_name} ->
          Info.strategy!(resource, strategy_name)

        :error ->
          resource
          |> Info.authentication_strategies()
          |> Enum.filter(&(&1.__struct__ == AshAuthentication.Strategy.ApiKey))
          |> case do
            [] ->
              raise "No api key strategies found on #{inspect(resource)}"

            [strategy] ->
              strategy

            _ ->
              raise "Multiple api key strategies found on #{inspect(resource)}, please specify which one to use."
          end
      end

    on_error =
      Keyword.get(opts, :on_error, &__MODULE__.on_error/2)

    %{
      resource: resource,
      source: source,
      param_name: param_name,
      required?: required?,
      header_prefix: header_prefix,
      on_error: on_error,
      strategy: strategy,
      assign: assign
    }
  end

  @doc """
  Process the connection and attempt to authenticate using the API key.
  """
  @impl true
  def call(conn, config) do
    case get_api_key(conn, config) do
      {:ok, api_key} ->
        case authenticate_api_key(conn, api_key, config.strategy) do
          {:ok, subject} ->
            conn
            |> Ash.PlugHelpers.set_actor(subject)
            |> Plug.Conn.assign(config.assign, subject)

          {:error, error} ->
            config[:on_error].(conn, error)
        end

      {:error, error} ->
        config[:on_error].(conn, error)

      :error ->
        if config[:required?] do
          config[:on_error].(conn, :missing_api_key)
        else
          conn
        end
    end
  end

  defp get_api_key(conn, %{source: :header, header_prefix: prefix}) do
    case Conn.get_req_header(conn, "authorization") do
      [header_value | _] ->
        if String.starts_with?(header_value, prefix) do
          {:ok, String.replace_prefix(header_value, prefix, "")}
        else
          {:error, :invalid_api_key}
        end

      _ ->
        :error
    end
  end

  defp get_api_key(conn, %{source: :query_param, param_name: param_name}) do
    case conn.params[param_name] do
      nil -> :error
      api_key -> {:ok, api_key}
    end
  end

  defp get_api_key(
         conn,
         %{
           source: :header_or_query_param
         } = config
       ) do
    with :error <- get_api_key(conn, %{config | source: :header}) do
      get_api_key(conn, %{config | source: :query_param})
    end
  end

  defp authenticate_api_key(conn, api_key, strategy) do
    params = %{
      api_key: api_key
    }

    tenant = PlugHelpers.get_tenant(conn)
    context = PlugHelpers.get_context(conn)

    Strategy.action(
      strategy,
      :sign_in,
      params,
      tenant: tenant,
      context: context
    )
  end
end
