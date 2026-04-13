# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Oidc do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy oidc my_provider"

    @shortdoc "Adds a generic OpenID Connect authentication strategy to your user resource"

    @moduledoc """
    #{@shortdoc}

    OIDC auto-discovers provider endpoints from the `.well-known/openid-configuration`
    URL, so you only need to provide the base URL of your OIDC provider.

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` - The user resource. Defaults to `YourApp.Accounts.User`
    * `--accounts`, `-a` - The accounts domain. Defaults to `YourApp.Accounts`
    * `--identity-field`, `-i` - The field used to identify the user. Defaults to `email`
    * `--base-url` - If provided, set as a literal in the strategy DSL instead of via env var
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [{:name, optional: true}],
        composes: [],
        schema: [
          accounts: :string,
          user: :string,
          identity_field: :string,
          name: :string,
          base_url: :string
        ],
        aliases: [a: :accounts, u: :user, i: :identity_field],
        defaults: [identity_field: "email"]
      }
    end

    # sobelow_skip ["DOS.BinToAtom"]
    def igniter(igniter) do
      options = parse_options(igniter)

      name_string = igniter.args.positional[:name] || options[:name]

      unless name_string do
        raise ArgumentError, """
        A provider name is required for the generic OIDC strategy.

        Via positional argument:
          mix ash_authentication.add_strategy.oidc my_provider

        Via flag:
          mix ash_authentication.add_strategy oidc --name my_provider
        """
      end

      name = String.to_atom(name_string)
      env_prefix = name |> to_string() |> String.upcase()

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          identity_resource =
            Module.concat(AshAuthentication.Igniter.parent_module(options[:user]), UserIdentity)

          secrets_module = Igniter.Project.Module.module_name(igniter, "Secrets")

          secret_pairs = [
            {:client_id, "#{env_prefix}_CLIENT_ID"},
            {:client_secret, "#{env_prefix}_CLIENT_SECRET"},
            {:redirect_uri, "#{env_prefix}_REDIRECT_URI"}
          ]

          {base_url_line, secret_pairs} =
            if options[:base_url] do
              {"base_url \"#{options[:base_url]}\"", secret_pairs}
            else
              {"base_url #{inspect(secrets_module)}",
               secret_pairs ++ [{:base_url, "#{env_prefix}_BASE_URL"}]}
            end

          igniter
          |> Ash.Resource.Igniter.add_new_attribute(options[:user], options[:identity_field], """
          attribute #{inspect(options[:identity_field])}, :ci_string do
            allow_nil? false
            public? true
          end
          """)
          |> AshAuthentication.Igniter.ensure_identity(options[:user], options[:identity_field])
          |> AshAuthentication.Igniter.ensure_user_identity_resource(
            options[:user],
            identity_resource
          )
          |> AshAuthentication.Igniter.add_oauth_register_action(
            options[:user],
            name,
            identity_field: options[:identity_field],
            identity_resource: identity_resource
          )
          |> AshAuthentication.Igniter.add_oauth_secrets(
            secrets_module,
            options[:user],
            name,
            secret_pairs
          )
          |> AshAuthentication.Igniter.add_new_strategy(options[:user], :oidc, name, """
          oidc :#{name} do
            client_id #{inspect(secrets_module)}
            client_secret #{inspect(secrets_module)}
            redirect_uri #{inspect(secrets_module)}
            #{base_url_line}
            identity_resource #{inspect(identity_resource)}
          end
          """)
          |> AshAuthentication.Igniter.codegen_for_strategy(name)
          |> Igniter.add_notice("""
          OIDC strategy "#{name}" setup:

          Set these environment variables:
            #{env_prefix}_CLIENT_ID=<your_client_id>
            #{env_prefix}_CLIENT_SECRET=<your_client_secret>
            #{env_prefix}_REDIRECT_URI=http://localhost:4000/auth
          #{unless options[:base_url], do: "  #{env_prefix}_BASE_URL=<your_oidc_provider_base_url>"}
          The provider's callback URL should be set to:
            http://localhost:4000/auth/#{name}/callback
          """)

        {false, igniter} ->
          Igniter.add_issue(igniter, """
          User module #{inspect(options[:user])} was not found.

          Perhaps you have not yet installed ash_authentication?
          """)
      end
    end

    defp parse_options(igniter) do
      options =
        igniter.args.options
        |> Keyword.put_new_lazy(:accounts, fn ->
          Igniter.Project.Module.module_name(igniter, "Accounts")
        end)

      options
      |> Keyword.put_new_lazy(:user, fn -> Module.concat(options[:accounts], User) end)
      |> Keyword.update(:identity_field, :email, &String.to_atom/1)
      |> Keyword.update!(:accounts, &AshAuthentication.Igniter.maybe_parse_module/1)
      |> Keyword.update!(:user, &AshAuthentication.Igniter.maybe_parse_module/1)
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Oidc do
    @shortdoc "Adds a generic OpenID Connect authentication strategy to your user resource"
    @moduledoc @shortdoc
    use Mix.Task

    def run(_argv) do
      Mix.shell().error("The task 'ash_authentication.add_strategy.oidc' requires igniter.")
      exit({:shutdown, 1})
    end
  end
end
