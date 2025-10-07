# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.Install do
    @example "mix igniter.install ash_authentication"
    @example_custom "mix igniter.install ash_authentication --auth-strategy magic_link,password --accounts MyApp.AshAccounts --user MyApp.AshAccounts.User --token MyApp.AshAccounts.Token"
    @shortdoc "Installs AshAuthentication. Invoke with `mix igniter.install ash_authentication`"

    @moduledoc """
    #{@shortdoc}

    ## Example

    To install with default settings:

    ```bash
    #{@example}
    ```

    To install with a custom domain and resources:

    ```bash
    #{@example_custom}

    ```

    ## Options

    * `--accounts` or `-a` - The domain that contains your resources. Defaults to `YourApp.Accounts`.
    * `--user` or `-u` - The resource that represents a user. Defaults to `<accounts>.User`.
    * `--token` or `-t` - The resource that represents a token. Defaults to `<accounts>.Token`.
    * `--auth-strategy` - The strategy or strategies to use for authentication.
      None by default, can be specified multiple times for more than one strategy.
      To add after installation, use `mix ash_authentication.add_strategy password`
    """

    use Igniter.Mix.Task

    @impl Igniter.Mix.Task
    def info(_argv, _parent) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        schema: [
          accounts: :string,
          user: :string,
          token: :string,
          yes: :boolean,
          auth_strategy: :csv
        ],
        composes: [
          "ash_authentication.add_strategy"
        ],
        aliases: [
          a: :accounts,
          u: :user,
          t: :token,
          y: :yes
        ]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      options =
        Keyword.put_new_lazy(igniter.args.options, :accounts, fn ->
          Igniter.Project.Module.module_name(igniter, "Accounts")
        end)
        |> parse_module_option(:accounts)

      options =
        options
        |> Keyword.put_new_lazy(:user, fn ->
          Module.concat(options[:accounts], User)
        end)
        |> Keyword.put_new_lazy(:token, fn ->
          Module.concat(options[:accounts], Token)
        end)
        |> parse_module_option(:user)
        |> parse_module_option(:token)

      accounts_domain = options[:accounts]
      token_resource = options[:token]
      user_resource = options[:user]
      secrets_module = Igniter.Project.Module.module_name(igniter, "Secrets")
      otp_app = Igniter.Project.Application.app_name(igniter)

      {igniter, resource_args, repo} = data_layer_args(igniter, options)

      igniter
      |> Igniter.Project.Formatter.import_dep(:ash_authentication)
      |> Igniter.Project.Formatter.add_formatter_plugin(Spark.Formatter)
      |> Igniter.Project.Config.configure("test.exs", :bcrypt_elixir, [:log_rounds], 1)
      |> Spark.Igniter.prepend_to_section_order(
        :"Ash.Resource",
        [:authentication, :token, :user_identity]
      )
      |> Igniter.compose_task(
        "ash.gen.domain",
        [inspect(accounts_domain), "--ignore-if-exists"] ++
          igniter.args.argv_flags ++ resource_args
      )
      |> generate_token_resource(token_resource, igniter.args.argv_flags, resource_args)
      |> Igniter.Project.Application.add_new_child(
        {AshAuthentication.Supervisor, otp_app: otp_app},
        after: fn _ -> true end
      )
      |> setup_data_layer(repo)
      |> generate_user_resource(
        user_resource,
        igniter.args.argv_flags,
        resource_args,
        token_resource,
        secrets_module,
        otp_app
      )
      |> Ash.Igniter.codegen("add_authentication_resources")
      |> add_strategies(options, igniter.args.argv_flags)
    end

    defp add_strategies(igniter, options, argv) do
      case List.wrap(options[:auth_strategy]) do
        [] ->
          Igniter.add_notice(igniter, """
          Don't forget to add at least one authentication strategy!

          You can use the task `mix ash_authentication.add_strategy`, or
          view the docs at https://hexdocs.pm/ash_authentication/get-started.html
          """)

        strategies ->
          Enum.reduce(strategies, igniter, fn strategy, igniter ->
            Igniter.compose_task(igniter, "ash_authentication.add_strategy", [strategy | argv])
          end)
      end
    end

    defp generate_user_resource(
           igniter,
           user_resource,
           argv,
           resource_args,
           token_resource,
           secrets_module,
           otp_app
         ) do
      dev_secret =
        :crypto.strong_rand_bytes(32) |> Base.encode64(padding: false) |> binary_part(0, 32)

      test_secret =
        :crypto.strong_rand_bytes(32) |> Base.encode64(padding: false) |> binary_part(0, 32)

      runtime_secret =
        {:code,
         Sourceror.parse_string!("""
         System.get_env("TOKEN_SIGNING_SECRET") ||
         raise "Missing environment variable `TOKEN_SIGNING_SECRET`!"
         """)}

      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, user_resource)

      if exists? do
        Igniter.add_notice(
          igniter,
          "User resource already exists: #{user_resource}, skipping creation."
        )
      else
        extensions =
          cond do
            Code.ensure_loaded?(AshPostgres.DataLayer) ->
              "postgres"

            Code.ensure_loaded?(AshSqlite.DataLayer) ->
              "sqlite"

            true ->
              nil
          end

        resource_args =
          if extensions do
            resource_args ++ ["--extend", extensions]
          else
            resource_args
          end

        igniter
        |> Igniter.compose_task(
          "ash.gen.resource",
          [
            inspect(user_resource),
            "--uuid-primary-key",
            "id",
            "--default-actions",
            "read"
          ] ++ argv ++ resource_args
        )
      end
      |> Igniter.compose_task(
        "ash.extend",
        [inspect(user_resource), "AshAuthentication,Ash.Policy.Authorizer"]
      )
      |> Ash.Resource.Igniter.add_new_action(user_resource, :get_by_subject, """
      read :get_by_subject do
        description "Get a user by the subject claim in a JWT"
        argument :subject, :string, allow_nil?: false
        get? true
        prepare AshAuthentication.Preparations.FilterBySubject
      end
      """)
      |> AshAuthentication.Igniter.add_new_add_on(
        user_resource,
        :log_out_everywhere,
        nil,
        """
        log_out_everywhere do
          apply_on_password_change? true
        end
        """
      )
      |> then(fn igniter ->
        if exists? do
          igniter
        else
          igniter
          |> Ash.Resource.Igniter.add_bypass(
            user_resource,
            quote do
              AshAuthentication.Checks.AshAuthenticationInteraction
            end,
            quote do
              authorize_if always()
            end
          )
        end
      end)
      |> Spark.Igniter.set_option(user_resource, [:authentication, :tokens, :enabled?], true)
      |> Spark.Igniter.set_option(
        user_resource,
        [:authentication, :tokens, :token_resource],
        token_resource
      )
      |> Spark.Igniter.set_option(
        user_resource,
        [:authentication, :tokens, :token_resource],
        token_resource
      )
      |> Spark.Igniter.set_option(
        user_resource,
        [:authentication, :tokens, :signing_secret],
        secrets_module
      )
      |> Spark.Igniter.set_option(
        user_resource,
        [:authentication, :tokens, :store_all_tokens?],
        true
      )
      |> Spark.Igniter.set_option(
        user_resource,
        [:authentication, :tokens, :require_token_presence_for_authentication?],
        true
      )
      |> Igniter.Project.Config.configure_new(
        "dev.exs",
        otp_app,
        [:token_signing_secret],
        dev_secret
      )
      |> Igniter.Project.Config.configure_new(
        "test.exs",
        otp_app,
        [:token_signing_secret],
        test_secret
      )
      |> Igniter.Project.Config.configure_runtime_env(
        :prod,
        otp_app,
        [:token_signing_secret],
        runtime_secret
      )
      |> AshAuthentication.Igniter.add_new_secret_from_env(
        secrets_module,
        user_resource,
        [:authentication, :tokens, :signing_secret],
        :token_signing_secret
      )
    end

    defp generate_token_resource(igniter, token_resource, _argv, resource_args) do
      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, token_resource)

      if exists? do
        Igniter.add_notice(
          igniter,
          "Token resource already exists: #{token_resource}, skipping creation."
        )
      else
        extensions =
          cond do
            Code.ensure_loaded?(AshPostgres.DataLayer) ->
              "postgres"

            Code.ensure_loaded?(AshSqlite.DataLayer) ->
              "sqlite"

            true ->
              nil
          end

        resource_args =
          if extensions do
            resource_args ++ ["--extend", extensions]
          else
            resource_args
          end

        igniter
        |> Igniter.compose_task(
          "ash.gen.resource",
          [
            inspect(token_resource),
            "--default-actions",
            "read"
          ] ++ resource_args
        )
      end
      |> Igniter.compose_task("ash.extend", [
        inspect(token_resource),
        "AshAuthentication.TokenResource,Ash.Policy.Authorizer"
      ])
      |> Ash.Resource.Igniter.add_new_attribute(token_resource, :jti, """
      attribute :jti, :string do
        primary_key? true
        public? true
        allow_nil? false
        sensitive? true
      end
      """)
      |> Ash.Resource.Igniter.add_new_attribute(token_resource, :subject, """
      attribute :subject, :string do
        allow_nil? false
        public? true
      end
      """)
      |> Ash.Resource.Igniter.add_new_attribute(token_resource, :expires_at, """
      attribute :expires_at, :utc_datetime do
        allow_nil? false
        public? true
      end
      """)
      |> Ash.Resource.Igniter.add_new_attribute(token_resource, :purpose, """
      attribute :purpose, :string do
        allow_nil? false
        public? true
      end
      """)
      |> Ash.Resource.Igniter.add_new_attribute(token_resource, :extra_data, """
      attribute :extra_data, :map do
        public? true
      end
      """)
      |> Ash.Resource.Igniter.add_new_attribute(token_resource, :created_at, """
      create_timestamp :created_at
      """)
      |> Ash.Resource.Igniter.add_new_attribute(token_resource, :updated_at, """
      update_timestamp :updated_at
      """)
      |> Ash.Resource.Igniter.add_new_action(token_resource, :expired, """
      read :expired do
        description "Look up all expired tokens."
        filter expr(expires_at < now())
      end
      """)
      |> then(fn igniter ->
        if exists? do
          igniter
        else
          igniter
          |> Ash.Resource.Igniter.add_bypass(
            token_resource,
            quote do
              AshAuthentication.Checks.AshAuthenticationInteraction
            end,
            quote do
              description "AshAuthentication can interact with the token resource"
              authorize_if always()
            end
          )
        end
      end)
      |> Ash.Resource.Igniter.add_new_action(token_resource, :get_token, """
      read :get_token do
        description "Look up a token by JTI or token, and an optional purpose."
        get? true
        argument :token, :string, sensitive?: true
        argument :jti, :string, sensitive?: true
        argument :purpose, :string, sensitive?: false

        prepare AshAuthentication.TokenResource.GetTokenPreparation
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(token_resource, :revoked?, """
      action :revoked?, :boolean do
        description "Returns true if a revocation token is found for the provided token"
        argument :token, :string, sensitive?: true
        argument :jti, :string, sensitive?: true

        run AshAuthentication.TokenResource.IsRevoked
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(token_resource, :revoke_token, """
      create :revoke_token do
        description "Revoke a token. Creates a revocation token corresponding to the provided token."
        accept [:extra_data]
        argument :token, :string, allow_nil?: false, sensitive?: true

        change AshAuthentication.TokenResource.RevokeTokenChange
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(token_resource, :revoke_jti, """
      create :revoke_jti do
        description "Revoke a token by JTI. Creates a revocation token corresponding to the provided jti."
        accept [:extra_data]
        argument :subject, :string, allow_nil?: false, sensitive?: true
        argument :jti, :string, allow_nil?: false, sensitive?: true

        change AshAuthentication.TokenResource.RevokeJtiChange
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(token_resource, :store_token, """
      create :store_token do
        description "Stores a token used for the provided purpose."
        accept [:extra_data, :purpose]
        argument :token, :string, allow_nil?: false, sensitive?: true
        change AshAuthentication.TokenResource.StoreTokenChange
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(token_resource, :expunge_expired, """
      destroy :expunge_expired do
        description "Deletes expired tokens."
        change filter(expr(expires_at < now()))
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(token_resource, :revoke_all_stored_for_subject, """
      update :revoke_all_stored_for_subject do
        description "Revokes all stored tokens for a specific subject."
        accept [:extra_data]
        argument :subject, :string, allow_nil?: false, sensitive?: true
        change AshAuthentication.TokenResource.RevokeAllStoredForSubjectChange
      end
      """)
    end

    cond do
      Code.ensure_loaded?(AshPostgres.Igniter) ->
        def setup_data_layer(igniter, repo) do
          igniter
          |> AshPostgres.Igniter.add_postgres_extension(repo, "citext")
        end

        def data_layer_args(igniter, opts) do
          {igniter, repo} =
            AshPostgres.Igniter.select_repo(igniter, generate?: true, yes: opts[:yes])

          {igniter, ["--repo", inspect(repo)], repo}
        end

      Code.ensure_loaded?(AshSqlite.Igniter) ->
        def setup_data_layer(igniter, _repo) do
          igniter
        end

        def data_layer_args(igniter, opts) do
          {igniter, repo} =
            AshSqlite.Igniter.select_repo(igniter, generate?: true, yes: opts[:yes])

          {igniter, ["--repo", inspect(repo)], repo}
        end

      true ->
        def setup_data_layer(igniter, _), do: igniter

        def data_layer_args(igniter, _) do
          {igniter, [], nil}
        end
    end

    defp parse_module_option(opts, option) do
      Keyword.update(opts, option, nil, fn value ->
        if is_binary(value) do
          Igniter.Project.Module.parse(value)
        else
          value
        end
      end)
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.Install do
    use Mix.Task

    @shortdoc "Installs AshAuthentication. Invoke with `mix igniter.install ash_authentication`"

    @moduledoc @shortdoc

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.install' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
