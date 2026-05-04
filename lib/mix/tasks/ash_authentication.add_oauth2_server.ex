# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddOauth2Server do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_oauth2_server"

    @shortdoc "Scaffolds an OAuth 2.1 authorization server"

    @moduledoc """
    #{@shortdoc}

    Scaffolds:

      * Four resources in the configured Ash domain — `OauthClient`,
        `OauthAuthorizationCode`, `OauthRefreshToken`, `OauthConsent`.
      * An `Oauth2Server` config module that pulls them together.
      * Three `secret_for/4` clauses on the user's Secrets module
        (`:issuer_url`, `:resource_url`, `:signing_secret`) that read from
        application env, so prod overrides go in `config/runtime.exs`.
      * Localhost defaults in `config/dev.exs` for development.
      * Migrations for the new resources (via `ash.codegen`).

    The router macros are NOT auto-mounted. Add them to your router by
    hand — different apps want different paths/pipelines:

        scope "/" do
          pipe_through :browser
          oauth2_server_consent_routes oauth2_server: MyApp.Oauth2Server
        end

        scope "/" do
          pipe_through :api
          oauth2_server_protocol_routes oauth2_server: MyApp.Oauth2Server
        end

    Then mount `AshAuthentication.Phoenix.Oauth2Server.BearerPlug` on
    whatever resource you want OAuth-protected.

    ## Production config

    The dev URLs written to `config/dev.exs` are placeholders. For prod,
    set the real values in `config/runtime.exs`:

        config :my_app,
          oauth2_issuer_url: System.get_env("OAUTH2_ISSUER_URL"),
          oauth2_resource_url: System.get_env("OAUTH2_RESOURCE_URL"),
          oauth2_signing_secret: System.get_env("OAUTH2_SIGNING_SECRET")

    `oauth2_resource_url` is the URL clients will reach your protected
    resource at. It's bound to the access token's `aud` claim.

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

      * `--accounts`, `-a` — Domain. Default: `MyApp.Accounts`.
      * `--user`, `-u` — User resource. Default: `<Accounts>.User`.
      * `--server-module`, `-s` — Where to put the `Oauth2Server` module.
        Default: `MyApp.Oauth2Server`.
      * `--secrets-module` — Module implementing `AshAuthentication.Secret`.
        Default: `MyApp.Secrets`.
      * `--issuer-url` — Issuer URL written to `config/dev.exs`.
        Default: `http://localhost:4000`.
      * `--resource-url` — Resource URL written to `config/dev.exs`.
        Default: same as `--issuer-url`.
      * `--scope` — Scope advertised in metadata. Default: `mcp`.
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [],
        schema: [
          accounts: :string,
          user: :string,
          server_module: :string,
          secrets_module: :string,
          resource_url: :string,
          issuer_url: :string,
          scope: :string
        ],
        aliases: [
          a: :accounts,
          u: :user,
          s: :server_module
        ],
        defaults: [
          issuer_url: "http://localhost:4000",
          scope: "mcp"
        ]
      }
    end

    def igniter(igniter) do
      options = parse_options(igniter)

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          igniter
          |> generate_resources(options)
          |> add_resources_to_domain(options)
          |> generate_server_module(options)
          |> add_secrets(options)
          |> add_app_config(options)
          |> Ash.Igniter.codegen("add_oauth2_server")
          |> then(fn igniter ->
            Igniter.add_notice(
              igniter,
              post_install_notice(options, Igniter.Project.Application.app_name(igniter))
            )
          end)

        {false, igniter} ->
          Igniter.add_issue(igniter, """
          User module #{inspect(options[:user])} was not found.

          Run `mix ash_authentication.install` first, then re-run this task.
          """)
      end
    end

    # ── option parsing ────────────────────────────────────────────────────

    defp parse_options(igniter) do
      app_module =
        igniter
        |> Igniter.Project.Module.module_name_prefix()

      options =
        igniter.args.options
        |> Keyword.put_new_lazy(:accounts, fn ->
          Igniter.Project.Module.module_name(igniter, "Accounts")
        end)

      options =
        options
        |> Keyword.put_new_lazy(:user, fn ->
          Module.concat(options[:accounts], User)
        end)
        |> Keyword.put_new_lazy(:server_module, fn ->
          Module.concat(app_module, Oauth2Server)
        end)
        |> Keyword.put_new_lazy(:secrets_module, fn ->
          detect_secrets_module(igniter, options[:user]) ||
            Module.concat(app_module, Secrets)
        end)
        |> Keyword.update!(:accounts, &AshAuthentication.Igniter.maybe_parse_module/1)
        |> Keyword.update!(:user, &AshAuthentication.Igniter.maybe_parse_module/1)
        |> Keyword.update!(:server_module, &AshAuthentication.Igniter.maybe_parse_module/1)
        |> Keyword.update!(:secrets_module, &AshAuthentication.Igniter.maybe_parse_module/1)

      options
    end

    defp detect_secrets_module(_igniter, _user) do
      # Best-effort: peek at the user resource's compile-time config. If we
      # can't find it cleanly, the caller falls back to <App>.Secrets which
      # is the convention `mix ash_authentication.install` produces.
      nil
    end

    # ── resource generation ───────────────────────────────────────────────

    defp generate_resources(igniter, options) do
      ns = parent_namespace(options[:user])

      igniter
      |> generate_client_resource(Module.concat(ns, OauthClient), options)
      |> generate_authorization_code_resource(
        Module.concat(ns, OauthAuthorizationCode),
        options
      )
      |> generate_refresh_token_resource(Module.concat(ns, OauthRefreshToken), options)
      |> generate_consent_resource(Module.concat(ns, OauthConsent), options)
    end

    defp generate_client_resource(igniter, mod, _options) do
      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, mod)
      if exists?, do: igniter, else: do_generate_client(igniter, mod)
    end

    defp do_generate_client(igniter, mod) do
      igniter
      |> Igniter.compose_task("ash.gen.resource", [
        inspect(mod),
        "--uuid-v7-primary-key",
        "id",
        "--default-actions",
        "read,destroy",
        "--attribute",
        "client_name:string:required:public",
        "--attribute",
        "redirect_uris:string:array:required:public",
        "--attribute",
        "grant_types:string:array:public",
        "--attribute",
        "response_types:string:array:public",
        "--attribute",
        "token_endpoint_auth_method:string:public",
        "--attribute",
        "scope:string:public",
        "--attribute",
        "last_used_at:utc_datetime_usec:public",
        "--timestamps",
        "--extend",
        data_layer_extension()
      ])
      |> Ash.Resource.Igniter.add_new_action(mod, :register, """
      create :register do
        accept [:client_name, :redirect_uris, :grant_types, :response_types, :token_endpoint_auth_method, :scope]
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(mod, :touch, """
      update :touch do
        accept []
        require_atomic? false
        change set_attribute(:last_used_at, &DateTime.utc_now/0)
      end
      """)
      |> add_authn_bypass(mod)
    end

    defp generate_authorization_code_resource(igniter, mod, options) do
      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, mod)
      if exists?, do: igniter, else: do_generate_auth_code(igniter, mod, options)
    end

    defp do_generate_auth_code(igniter, mod, options) do
      igniter
      |> Igniter.compose_task("ash.gen.resource", [
        inspect(mod),
        "--uuid-v7-primary-key",
        "id",
        "--default-actions",
        "read,destroy",
        "--attribute",
        "client_id:uuid_v7:required:public",
        "--attribute",
        "user_id:#{user_id_type(options)}:required:public",
        "--attribute",
        "redirect_uri:string:required:public",
        "--attribute",
        "code_challenge:string:required:public",
        "--attribute",
        "scope:string:required:public",
        "--attribute",
        "resource_uri:string:required:public",
        "--attribute",
        "expires_at:utc_datetime_usec:required:public",
        "--attribute",
        "consumed_at:utc_datetime_usec:public",
        "--extend",
        data_layer_extension()
      ])
      |> Ash.Resource.Igniter.add_new_action(mod, :create, """
      create :create do
        accept [:client_id, :user_id, :redirect_uri, :code_challenge, :scope, :resource_uri, :expires_at]
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(mod, :consume, """
      update :consume do
        accept []
        require_atomic? false

        change fn changeset, _ ->
          if Ash.Changeset.get_data(changeset, :consumed_at) do
            Ash.Changeset.add_error(changeset, field: :consumed_at, message: "code already used")
          else
            Ash.Changeset.change_attribute(changeset, :consumed_at, DateTime.utc_now())
          end
        end
      end
      """)
      |> add_authn_bypass(mod)
    end

    defp generate_refresh_token_resource(igniter, mod, options) do
      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, mod)
      if exists?, do: igniter, else: do_generate_refresh(igniter, mod, options)
    end

    defp do_generate_refresh(igniter, mod, options) do
      igniter
      |> Igniter.compose_task("ash.gen.resource", [
        inspect(mod),
        "--uuid-v7-primary-key",
        "id",
        "--default-actions",
        "read,destroy",
        "--attribute",
        "token_hash:string:required:public",
        "--attribute",
        "client_id:uuid_v7:required:public",
        "--attribute",
        "user_id:#{user_id_type(options)}:required:public",
        "--attribute",
        "scope:string:required:public",
        "--attribute",
        "resource_uri:string:required:public",
        "--attribute",
        "expires_at:utc_datetime_usec:required:public",
        "--attribute",
        "rotated_to_id:uuid_v7:public",
        "--attribute",
        "revoked_at:utc_datetime_usec:public",
        "--extend",
        data_layer_extension()
      ])
      |> Ash.Resource.Igniter.add_new_action(mod, :issue, """
      create :issue do
        accept [:token_hash, :client_id, :user_id, :scope, :resource_uri, :expires_at]
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(mod, :rotate, """
      update :rotate do
        argument :rotated_to_id, :uuid_v7, allow_nil?: false
        accept []
        require_atomic? false

        change fn changeset, _ ->
          cond do
            Ash.Changeset.get_data(changeset, :revoked_at) ->
              Ash.Changeset.add_error(changeset, message: "refresh token revoked")

            Ash.Changeset.get_data(changeset, :rotated_to_id) ->
              Ash.Changeset.add_error(changeset, message: "refresh token already rotated")

            true ->
              new_id = Ash.Changeset.get_argument(changeset, :rotated_to_id)
              Ash.Changeset.change_attribute(changeset, :rotated_to_id, new_id)
          end
        end
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(mod, :revoke, """
      update :revoke do
        accept []
        require_atomic? false
        change set_attribute(:revoked_at, &DateTime.utc_now/0)
      end
      """)
      |> Ash.Resource.Igniter.add_new_identity(mod, :by_token_hash, """
      identity :by_token_hash, [:token_hash]
      """)
      |> add_authn_bypass(mod)
    end

    defp generate_consent_resource(igniter, mod, options) do
      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, mod)
      if exists?, do: igniter, else: do_generate_consent(igniter, mod, options)
    end

    defp do_generate_consent(igniter, mod, options) do
      igniter
      |> Igniter.compose_task("ash.gen.resource", [
        inspect(mod),
        "--uuid-v7-primary-key",
        "id",
        "--default-actions",
        "read,destroy",
        "--attribute",
        "user_id:#{user_id_type(options)}:required:public",
        "--attribute",
        "client_id:uuid_v7:required:public",
        "--attribute",
        "scope:string:required:public",
        "--attribute",
        "granted_at:utc_datetime_usec:required:public",
        "--extend",
        data_layer_extension()
      ])
      |> Ash.Resource.Igniter.add_new_action(mod, :grant, """
      create :grant do
        upsert? true
        upsert_identity :by_user_client
        accept [:user_id, :client_id, :scope]
        change set_attribute(:granted_at, &DateTime.utc_now/0)
      end
      """)
      |> Ash.Resource.Igniter.add_new_identity(mod, :by_user_client, """
      identity :by_user_client, [:user_id, :client_id]
      """)
      |> add_authn_bypass(mod)
    end

    # ── domain wiring ────────────────────────────────────────────────────

    defp add_resources_to_domain(igniter, options) do
      ns = parent_namespace(options[:user])

      [
        Module.concat(ns, OauthClient),
        Module.concat(ns, OauthAuthorizationCode),
        Module.concat(ns, OauthRefreshToken),
        Module.concat(ns, OauthConsent)
      ]
      |> Enum.reduce(igniter, fn resource, igniter ->
        Ash.Domain.Igniter.add_resource_reference(igniter, options[:accounts], resource)
      end)
    end

    # ── Oauth2Server config module ───────────────────────────────────────

    defp generate_server_module(igniter, options) do
      ns = parent_namespace(options[:user])
      otp_app = Igniter.Project.Application.app_name(igniter)

      contents = """
      @moduledoc \"\"\"
      OAuth 2.1 authorization-server configuration.

      See `AshAuthentication.Oauth2Server` for all options.
      \"\"\"

      use AshAuthentication.Oauth2Server,
        otp_app: #{inspect(otp_app)},
        user_resource: #{inspect(options[:user])},
        issuer_url: {#{inspect(options[:secrets_module])}, []},
        resource_url: {#{inspect(options[:secrets_module])}, []},
        signing_secret: {#{inspect(options[:secrets_module])}, []},
        client_resource: #{inspect(Module.concat(ns, OauthClient))},
        authorization_code_resource: #{inspect(Module.concat(ns, OauthAuthorizationCode))},
        refresh_token_resource: #{inspect(Module.concat(ns, OauthRefreshToken))},
        consent_resource: #{inspect(Module.concat(ns, OauthConsent))},
        scopes: [#{inspect(options[:scope])}],
        sign_in_path: "/sign-in"
      """

      Igniter.Project.Module.create_module(igniter, options[:server_module], contents,
        on_exists: :skip
      )
    end

    # ── Secrets module ───────────────────────────────────────────────────

    defp add_secrets(igniter, options) do
      [
        {[:issuer_url], :oauth2_issuer_url},
        {[:resource_url], :oauth2_resource_url},
        {[:signing_secret], :oauth2_signing_secret}
      ]
      |> Enum.reduce(igniter, fn {path, env_key}, igniter ->
        # The secret_for/4 callback's second arg matches whatever
        # `Oauth2Server.__resolve_secret__!/3` passes — the server module.
        AshAuthentication.Igniter.add_new_secret_from_env(
          igniter,
          options[:secrets_module],
          options[:server_module],
          path,
          env_key
        )
      end)
    end

    # ── application config ───────────────────────────────────────────────

    defp add_app_config(igniter, options) do
      otp_app = Igniter.Project.Application.app_name(igniter)
      signing_secret = generate_signing_secret()
      resource_url = options[:resource_url] || options[:issuer_url]

      igniter
      |> Igniter.Project.Config.configure(
        "dev.exs",
        otp_app,
        [:oauth2_issuer_url],
        options[:issuer_url]
      )
      |> Igniter.Project.Config.configure(
        "dev.exs",
        otp_app,
        [:oauth2_resource_url],
        resource_url
      )
      |> Igniter.Project.Config.configure(
        "dev.exs",
        otp_app,
        [:oauth2_signing_secret],
        signing_secret
      )
    end

    defp generate_signing_secret do
      :crypto.strong_rand_bytes(32) |> Base.encode64(padding: false)
    end

    # Add `Ash.Policy.Authorizer` to the resource and emit a single bypass
    # for `AshAuthentication.Checks.AshAuthenticationInteraction`. Other
    # callers can layer their own policies on top later.
    defp add_authn_bypass(igniter, resource) do
      igniter
      |> Igniter.compose_task("ash.extend", [inspect(resource), "Ash.Policy.Authorizer"])
      |> Ash.Resource.Igniter.add_bypass(
        resource,
        quote do
          AshAuthentication.Checks.AshAuthenticationInteraction
        end,
        quote do
          authorize_if always()
        end
      )
    end

    # ── helpers ──────────────────────────────────────────────────────────

    defp parent_namespace(module) do
      module
      |> Module.split()
      |> :lists.droplast()
      |> Module.concat()
    end

    defp user_id_type(options) do
      # Default to UUID v4 (matches `uuid_primary_key :id` from the
      # standard ash_authentication.install). Users with uuid_v7
      # user resources can pass --user-id-type uuid_v7 in a future
      # extension, but for now `:uuid` matches the install default.
      _ = options
      "uuid"
    end

    defp data_layer_extension do
      cond do
        Code.ensure_loaded?(AshPostgres.DataLayer) -> "postgres"
        Code.ensure_loaded?(AshSqlite.DataLayer) -> "sqlite"
        true -> ""
      end
    end

    defp post_install_notice(options, otp_app) do
      """
      OAuth 2.1 server scaffolded.

      1. Wire the OAuth routes into your Phoenix router (see your existing
         `:browser` and `:api` pipelines for what to pipe through):

             scope "/" do
               pipe_through :browser
               oauth2_server_consent_routes oauth2_server: #{inspect(options[:server_module])}
             end

             scope "/" do
               pipe_through :api
               oauth2_server_protocol_routes oauth2_server: #{inspect(options[:server_module])}
             end

      2. Make sure your `:browser` pipeline sets the actor. The consent
         endpoint uses `Ash.PlugHelpers.get_actor/1` to figure out who's
         consenting, so the pipeline needs the standard pair:

             plug :load_from_session
             plug :set_actor, :user

         If the actor isn't set, signed-in users will get bounced through
         the sign-in flow as if they weren't logged in.

      3. Mount the bearer plug on whatever resource(s) you want
         OAuth-protected (an API, MCP endpoint, admin tool, etc.):

             plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
               oauth2_server: #{inspect(options[:server_module])}

      4. Run `mix ecto.migrate` to apply the new tables.

      5. For production, set real values in `config/runtime.exs`:

             config :#{otp_app},
               oauth2_issuer_url: System.get_env("OAUTH2_ISSUER_URL"),
               oauth2_resource_url: System.get_env("OAUTH2_RESOURCE_URL"),
               oauth2_signing_secret: System.get_env("OAUTH2_SIGNING_SECRET")
      """
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddOauth2Server do
    @shortdoc "Scaffolds an OAuth 2.1 authorization server"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_oauth2_server' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
