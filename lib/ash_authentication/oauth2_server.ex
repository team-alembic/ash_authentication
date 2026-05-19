# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server do
  @moduledoc """
  An OAuth 2.1 authorization server, configured per app via a single module.

  The authorization server is a singleton — one per app, not one per user
  resource — so its config lives on its own module rather than on a strategy
  block of a user resource.

  ## Usage

  ```elixir
  defmodule MyApp.Oauth2Server do
    use AshAuthentication.Oauth2Server,
      otp_app: :my_app,
      user_resource: MyApp.Accounts.User,
      issuer_url: {MyApp.Secrets, []},
      resource_url: {MyApp.Secrets, []},
      signing_secret: {MyApp.Secrets, []},
      client_resource: MyApp.Accounts.OAuthClient,
      authorization_code_resource: MyApp.Accounts.OAuthAuthorizationCode,
      refresh_token_resource: MyApp.Accounts.OAuthRefreshToken,
      consent_resource: MyApp.Accounts.OAuthConsent,
      scopes: ["mcp"]
  end
  ```

  Required keys: `:otp_app`, `:user_resource`, `:issuer_url`, `:resource_url`,
  `:signing_secret`, `:client_resource`, `:authorization_code_resource`,
  `:refresh_token_resource`, `:consent_resource`.

  Optional keys (with defaults):

  | Key | Default | Notes |
  |---|---|---|
  | `:scopes` | `["mcp"]` | List of scope strings advertised in metadata |
  | `:access_token_lifetime` | `{1, :hour}` | `{integer, unit}` where unit is `:second`, `:minute`, `:hour`, or `:day` |
  | `:refresh_token_lifetime` | `{30, :days}` | |
  | `:authorization_code_lifetime` | `{10, :minutes}` | |
  | `:dcr_always_return_client_secret?` | `false` | Workaround for clients that misbehave when `client_secret` is absent for `auth_method: none`. See https://community.openai.com/t/1366118 |
  | `:sign_in_path` | `nil` | Path to redirect unauthenticated `/oauth/authorize` requests to. When `nil`, returns 401. |
  | `:initial_access_token` | `nil` | When set, `POST /oauth/register` requires the request to present a matching `Authorization: Bearer …` token (RFC 7591 §3). When `nil` (default), dynamic client registration is open — see the trust-model note below. |

  ## Dynamic client registration

  By default, `POST /oauth/register` is open — any client can register
  itself with its desired `redirect_uris`. This is the standard mode for
  OAuth dynamic client registration (RFC 7591) and matches what MCP and
  most similar flows expect; user-facing protection lives further down
  in the consent screen and the audience-bound access tokens.

  If you'd rather gate registration (e.g. only your own deployment
  infrastructure can register clients), set `:initial_access_token` and
  require requests to present a matching `Authorization: Bearer …`
  header (RFC 7591 §3).

  ### Secret values

  `:issuer_url`, `:resource_url`, `:signing_secret`, and
  `:initial_access_token` accept any of:

    * a literal string — resolved at compile time
    * a `{Module, opts}` tuple where `Module` implements
      `AshAuthentication.Secret` — resolved at call time
    * a 2-arity anonymous function — resolved at call time
    * an MFA tuple `{Module, :function, [extra_args]}` — resolved at call time

  See `AshAuthentication.Secret` for details.

  ## Reading the config

  Each option is exposed as a function on the module:

      iex> MyApp.Oauth2Server.user_resource()
      MyApp.Accounts.User
      iex> MyApp.Oauth2Server.issuer_url()
      "https://app.example.com"
      iex> MyApp.Oauth2Server.access_token_lifetime()
      3600
  """

  alias AshAuthentication.Oauth2Server

  @required_keys [
    :otp_app,
    :user_resource,
    :issuer_url,
    :resource_url,
    :signing_secret,
    :client_resource,
    :authorization_code_resource,
    :refresh_token_resource,
    :consent_resource
  ]

  @doc false
  def __default_opts__ do
    [
      scopes: ["mcp"],
      access_token_lifetime: {1, :hour},
      refresh_token_lifetime: {30, :days},
      authorization_code_lifetime: {10, :minutes},
      dcr_always_return_client_secret?: false,
      sign_in_path: nil,
      initial_access_token: nil
    ]
  end

  @doc false
  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      Oauth2Server.__validate_opts__!(__MODULE__, opts)

      @oauth2_server_opts Keyword.merge(Oauth2Server.__default_opts__(), opts)

      def otp_app, do: Keyword.fetch!(@oauth2_server_opts, :otp_app)
      def user_resource, do: Keyword.fetch!(@oauth2_server_opts, :user_resource)
      def client_resource, do: Keyword.fetch!(@oauth2_server_opts, :client_resource)

      def authorization_code_resource,
        do: Keyword.fetch!(@oauth2_server_opts, :authorization_code_resource)

      def refresh_token_resource,
        do: Keyword.fetch!(@oauth2_server_opts, :refresh_token_resource)

      def consent_resource, do: Keyword.fetch!(@oauth2_server_opts, :consent_resource)
      def scopes, do: Keyword.fetch!(@oauth2_server_opts, :scopes)
      def sign_in_path, do: Keyword.fetch!(@oauth2_server_opts, :sign_in_path)

      def dcr_always_return_client_secret?,
        do: Keyword.fetch!(@oauth2_server_opts, :dcr_always_return_client_secret?)

      def access_token_lifetime,
        do: Oauth2Server.__lifetime_seconds__(@oauth2_server_opts[:access_token_lifetime])

      def refresh_token_lifetime,
        do: Oauth2Server.__lifetime_seconds__(@oauth2_server_opts[:refresh_token_lifetime])

      def authorization_code_lifetime,
        do:
          Oauth2Server.__lifetime_seconds__(@oauth2_server_opts[:authorization_code_lifetime])

      def issuer_url do
        @oauth2_server_opts
        |> Keyword.fetch!(:issuer_url)
        |> Oauth2Server.__resolve_secret__!(__MODULE__, [:issuer_url])
        |> Oauth2Server.__normalize_url__()
      end

      def resource_url do
        @oauth2_server_opts
        |> Keyword.fetch!(:resource_url)
        |> Oauth2Server.__resolve_secret__!(__MODULE__, [:resource_url])
        |> Oauth2Server.__normalize_url__()
      end

      def signing_secret do
        @oauth2_server_opts
        |> Keyword.fetch!(:signing_secret)
        |> Oauth2Server.__resolve_secret__!(__MODULE__, [:signing_secret])
      end

      @doc """
      The configured initial access token, or `nil` if dynamic client
      registration is open.

      When non-nil, `POST /oauth/register` requires the request to present
      the matching token in `Authorization: Bearer …`. See RFC 7591 §3.
      """
      def initial_access_token do
        case @oauth2_server_opts[:initial_access_token] do
          nil ->
            nil

          spec ->
            Oauth2Server.__resolve_secret__!(spec, __MODULE__, [:initial_access_token])
        end
      end

      def __oauth2_server__, do: true
    end
  end

  @doc false
  def __validate_opts__!(module, opts) do
    missing = @required_keys -- Keyword.keys(opts)

    if missing != [] do
      raise CompileError,
        description:
          "#{inspect(module)} is missing required `use AshAuthentication.Oauth2Server` options: " <>
            inspect(missing)
    end

    case Keyword.fetch!(opts, :otp_app) do
      atom when is_atom(atom) -> :ok
      other -> raise CompileError, description: "expected `:otp_app` to be an atom, got: #{inspect(other)}"
    end

    Enum.each(
      [:user_resource, :client_resource, :authorization_code_resource, :refresh_token_resource, :consent_resource],
      fn key ->
        case Keyword.fetch!(opts, key) do
          atom when is_atom(atom) and not is_nil(atom) -> :ok
          other -> raise CompileError, description: "expected `#{inspect(key)}` to be a module, got: #{inspect(other)}"
        end
      end
    )

    :ok
  end

  @doc false
  @lifetime_units %{
    second: 1,
    seconds: 1,
    minute: 60,
    minutes: 60,
    hour: 3_600,
    hours: 3_600,
    day: 86_400,
    days: 86_400
  }
  def __lifetime_seconds__(seconds) when is_integer(seconds) and seconds > 0, do: seconds

  def __lifetime_seconds__({n, unit}) when is_integer(n) and n > 0 do
    multiplier = Map.fetch!(@lifetime_units, unit)
    n * multiplier
  end

  def __lifetime_seconds__(other),
    do: raise(ArgumentError, "invalid lifetime: #{inspect(other)}")

  @doc false
  def __resolve_secret__!(value, module, path) do
    case resolve_secret(value, module, path) do
      {:ok, resolved} -> resolved
      :error -> raise "Oauth2Server: failed to resolve secret at #{inspect(path)} on #{inspect(module)}"
      {:error, reason} -> raise "Oauth2Server: failed to resolve secret at #{inspect(path)}: #{inspect(reason)}"
    end
  end

  defp resolve_secret(value, _module, _path) when is_binary(value), do: {:ok, value}

  defp resolve_secret({mod, opts}, module, path) when is_atom(mod) and is_list(opts) do
    Code.ensure_loaded(mod)

    if function_exported?(mod, :__secret_for_arity__, 0) do
      AshAuthentication.Secret.secret_for(mod, path, module, opts, %{})
    else
      {:error, {:not_a_secret_module, mod}}
    end
  end

  defp resolve_secret({mod, fun, args}, module, path)
       when is_atom(mod) and is_atom(fun) and is_list(args) do
    case apply(mod, fun, [path, module | args]) do
      {:ok, value} -> {:ok, value}
      :error -> :error
      other -> {:ok, other}
    end
  end

  defp resolve_secret(fun, module, path) when is_function(fun, 2) do
    case fun.(path, module) do
      {:ok, value} -> {:ok, value}
      :error -> :error
      other -> {:ok, other}
    end
  end

  defp resolve_secret(other, _module, _path), do: {:error, {:invalid_secret, other}}

  @doc """
  Canonicalize a URL for redirect_uri / resource / issuer comparison.

  Per RFC 8252 §7.3 and RFC 3986 §6 — lowercase scheme + host, elide
  default ports (80 for http, 443 for https), strip trailing slash off
  an empty path, drop the fragment. Two URLs that compare equal after
  this canonicalization are considered equivalent.
  """
  def __normalize_url__(url) when is_binary(url) do
    uri = URI.parse(url)
    scheme = uri.scheme && String.downcase(uri.scheme)

    %{
      uri
      | scheme: scheme,
        host: uri.host && String.downcase(uri.host),
        port: normalize_port(scheme, uri.port),
        path: normalize_path(uri.path),
        fragment: nil
    }
    |> URI.to_string()
    |> String.trim_trailing("/")
  end

  defp normalize_path(nil), do: nil
  defp normalize_path("/"), do: nil
  defp normalize_path(path), do: path

  defp normalize_port("http", 80), do: nil
  defp normalize_port("https", 443), do: nil
  defp normalize_port(_, port), do: port
end
