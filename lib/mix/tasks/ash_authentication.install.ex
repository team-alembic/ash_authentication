# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.Install do
    @example "mix igniter.install ash_authentication"
    @shortdoc "Installs AshAuthentication. Invoke with `mix igniter.install ash_authentication`"

    @moduledoc """
    #{@shortdoc}

    ## Example

    ```bash
    #{@example}
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
    def igniter(igniter, argv) do
      options = options!(argv)

      options =
        Keyword.put_new_lazy(options, :accounts, fn ->
          Igniter.Project.Module.module_name(igniter, "Accounts")
        end)

      options =
        options
        |> Keyword.put_new_lazy(:user, fn ->
          Module.concat(options[:accounts], User)
        end)
        |> Keyword.put_new_lazy(:token, fn ->
          Module.concat(options[:accounts], Token)
        end)
        |> parse_module_option(:accounts)
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
      |> Spark.Igniter.prepend_to_section_order(
        :"Ash.Resource",
        [:authentication, :tokens]
      )
      |> Igniter.compose_task(
        "ash.gen.domain",
        [inspect(accounts_domain), "--ignore-if-exists"] ++ argv ++ resource_args
      )
      |> generate_token_resource(token_resource, argv, resource_args)
      |> Igniter.Project.Application.add_new_child(
        {AshAuthentication.Supervisor, otp_app: otp_app},
        after: fn _ -> true end
      )
      |> setup_data_layer(repo)
      |> generate_user_resource(
        user_resource,
        argv,
        resource_args,
        token_resource,
        secrets_module,
        otp_app
      )
      |> Ash.Igniter.codegen("add_authentication_resources")
      |> add_strategies(options, argv)
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
      case Igniter.Project.Module.find_module(igniter, user_resource) do
        {:ok, {igniter, _, _}} ->
          Igniter.add_warning(
            igniter,
            "User resource already exists: #{user_resource}, skipping creation."
          )

        {:error, igniter} ->
          extensions = "AshAuthentication,Ash.Policy.Authorizer"

          extensions =
            cond do
              Code.ensure_loaded?(AshPostgres.DataLayer) ->
                "postgres,#{extensions}"

              Code.ensure_loaded?(AshSqlite.DataLayer) ->
                "sqlite,#{extensions}"

              true ->
                extensions
            end

          dev_secret =
            :crypto.strong_rand_bytes(32) |> Base.encode64(padding: false) |> binary_part(0, 32)

          test_secret =
            :crypto.strong_rand_bytes(32) |> Base.encode64(padding: false) |> binary_part(0, 32)

          runtime_secret =
            {:code,
             quote do
               System.get_env("TOKEN_SIGNING_SECRET") ||
                 raise "Missing environment variable `TOKEN_SIGNING_SECRET`!"
             end}

          igniter
          |> Igniter.compose_task(
            "ash.gen.resource",
            [
              inspect(user_resource),
              "--uuid-primary-key",
              "id",
              "--default-actions",
              "read",
              "--extend",
              extensions
            ] ++ argv ++ resource_args
          )
          |> Ash.Resource.Igniter.add_action(user_resource, """
          read :get_by_subject do
            description "Get a user by the subject claim in a JWT"
            argument :subject, :string, allow_nil?: false
            get? true
            prepare AshAuthentication.Preparations.FilterBySubject
          end
          """)
          |> AshAuthentication.Igniter.add_new_add_on(
            user_resource,
            nil,
            :log_out_everywhere,
            """
            log_out_everywhere do
              apply_on_password_change? true
            end
            """
          )
          |> Ash.Resource.Igniter.add_bypass(
            user_resource,
            quote do
              AshAuthentication.Checks.AshAuthenticationInteraction
            end,
            quote do
              authorize_if always()
            end
          )
          |> Ash.Resource.Igniter.add_policy(
            user_resource,
            quote do
              always()
            end,
            quote do
              forbid_if always()
            end
          )
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
          |> AshAuthentication.Igniter.add_secret_from_env(
            secrets_module,
            user_resource,
            [:authentication, :tokens, :signing_secret],
            :token_signing_secret
          )
      end
    end

    defp generate_token_resource(igniter, token_resource, _argv, resource_args) do
      case Igniter.Project.Module.find_module(igniter, token_resource) do
        {:ok, {igniter, _, _}} ->
          Igniter.add_warning(
            igniter,
            "Token resource already exists: #{token_resource}, skipping creation."
          )

        {:error, igniter} ->
          extensions = "AshAuthentication.TokenResource,Ash.Policy.Authorizer"

          extensions =
            cond do
              Code.ensure_loaded?(AshPostgres.DataLayer) ->
                "postgres,#{extensions}"

              Code.ensure_loaded?(AshSqlite.DataLayer) ->
                "sqlite,#{extensions}"

              true ->
                extensions
            end

          igniter
          |> Igniter.compose_task(
            "ash.gen.resource",
            [
              inspect(token_resource),
              "--default-actions",
              "read",
              "--extend",
              extensions,
              "--attribute",
              "jti:string:primary_key:public:required:sensitive",
              "--attribute",
              "subject:string:required:public",
              "--attribute",
              "expires_at:utc_datetime:required:public",
              "--attribute",
              "purpose:string:required:public",
              "--attribute",
              "extra_data:map:public",
              "--timestamps"
            ] ++ resource_args
          )
          # Consider moving to the extension's `install/5` callback, but we need
          # to only run it if the resource is being created which we can't
          # currently tell in that callback
          |> Ash.Resource.Igniter.add_action(token_resource, """
          read :expired do
            description "Look up all expired tokens."
            filter expr(expires_at < now())
          end
          """)
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
          |> Ash.Resource.Igniter.add_policy(
            token_resource,
            quote do
              always()
            end,
            quote do
              description "No one aside from AshAuthentication can interact with the tokens resource."
              forbid_if always()
            end
          )
          |> Ash.Resource.Igniter.add_action(token_resource, """
          read :get_token do
            description "Look up a token by JTI or token, and an optional purpose."
            get? true
            argument :token, :string, sensitive?: true
            argument :jti, :string, sensitive?: true
            argument :purpose, :string, sensitive?: false

            prepare AshAuthentication.TokenResource.GetTokenPreparation
          end
          """)
          |> Ash.Resource.Igniter.add_action(token_resource, """
          action :revoked?, :boolean do
            description "Returns true if a revocation token is found for the provided token"
            argument :token, :string, sensitive?: true
            argument :jti, :string, sensitive?: true

            run AshAuthentication.TokenResource.IsRevoked
          end
          """)
          |> Ash.Resource.Igniter.add_action(token_resource, """
          create :revoke_token do
            description "Revoke a token. Creates a revocation token corresponding to the provided token."
            accept [:extra_data]
            argument :token, :string, allow_nil?: false, sensitive?: true

            change AshAuthentication.TokenResource.RevokeTokenChange
          end
          """)
          |> Ash.Resource.Igniter.add_action(token_resource, """
          create :store_token do
            description "Stores a token used for the provided purpose."
            accept [:extra_data, :purpose]
            argument :token, :string, allow_nil?: false, sensitive?: true
            change AshAuthentication.TokenResource.StoreTokenChange
          end
          """)
          |> Ash.Resource.Igniter.add_action(token_resource, """
          destroy :expunge_expired do
            description "Deletes expired tokens."
            change filter(expr(expires_at < now()))
          end
          """)
          |> Ash.Resource.Igniter.add_action(token_resource, """
          update :revoke_all_stored_for_subject do
            description "Revokes all stored tokens for a specific subject."
            accept [:extra_data]
            argument :subject, :string, allow_nil?: false, sensitive?: true
            change AshAuthentication.TokenResource.RevokeAllStoredForSubjectChange
          end
          """)
      end
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
