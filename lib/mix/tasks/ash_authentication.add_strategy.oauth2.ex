# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Oauth2 do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy oauth2 my_provider"

    @shortdoc "Adds a generic OAuth2 authentication strategy to your user resource"

    @moduledoc """
    #{@shortdoc}

    Unlike OIDC, generic OAuth2 does not auto-discover provider endpoints.
    You can provide the URLs via CLI flags (set as literals in the DSL) or
    leave them to be configured via environment variables.

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` - The user resource. Defaults to `YourApp.Accounts.User`
    * `--accounts`, `-a` - The accounts domain. Defaults to `YourApp.Accounts`
    * `--identity-field`, `-i` - The field used to identify the user. Defaults to `email`
    * `--base-url` - Base URL of the OAuth2 provider
    * `--authorize-url` - Authorization endpoint URL (relative to base_url or absolute)
    * `--token-url` - Token endpoint URL (relative to base_url or absolute)
    * `--user-url` - User info endpoint URL (relative to base_url or absolute)
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [:name],
        composes: [],
        schema: [
          accounts: :string,
          user: :string,
          identity_field: :string,
          base_url: :string,
          authorize_url: :string,
          token_url: :string,
          user_url: :string
        ],
        aliases: [a: :accounts, u: :user, i: :identity_field],
        defaults: [identity_field: "email"]
      }
    end

    # sobelow_skip ["DOS.BinToAtom"]
    def igniter(igniter) do
      options = parse_options(igniter)
      name = String.to_atom(igniter.args.positional[:name])
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

          {url_lines, secret_pairs} =
            build_url_config(options, secrets_module, env_prefix, secret_pairs)

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
          |> AshAuthentication.Igniter.add_new_strategy(options[:user], :oauth2, name, """
          oauth2 :#{name} do
            client_id #{inspect(secrets_module)}
            client_secret #{inspect(secrets_module)}
            redirect_uri #{inspect(secrets_module)}
            #{url_lines}
            identity_resource #{inspect(identity_resource)}
          end
          """)
          |> AshAuthentication.Igniter.codegen_for_strategy(name)
          |> Igniter.add_notice("""
          OAuth2 strategy "#{name}" setup:

          Set these environment variables:
            #{env_prefix}_CLIENT_ID=<your_client_id>
            #{env_prefix}_CLIENT_SECRET=<your_client_secret>
            #{env_prefix}_REDIRECT_URI=http://localhost:4000/auth
          #{url_env_notice(options, env_prefix)}
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

    defp build_url_config(options, secrets_module, env_prefix, secret_pairs) do
      url_fields = [
        {:base_url, "BASE_URL"},
        {:authorize_url, "AUTHORIZE_URL"},
        {:token_url, "TOKEN_URL"},
        {:user_url, "USER_URL"}
      ]

      Enum.reduce(url_fields, {"", secret_pairs}, fn {field, env_suffix}, {lines, pairs} ->
        case Keyword.get(options, field) do
          nil ->
            env_var = "#{env_prefix}_#{env_suffix}"
            line = "#{field} #{inspect(secrets_module)}"
            {"#{lines}#{line}\n    ", pairs ++ [{field, env_var}]}

          value ->
            line = "#{field} \"#{value}\""
            {"#{lines}#{line}\n    ", pairs}
        end
      end)
    end

    defp url_env_notice(options, env_prefix) do
      [
        {:base_url, "BASE_URL", "<provider_base_url>"},
        {:authorize_url, "AUTHORIZE_URL", "<authorize_endpoint>"},
        {:token_url, "TOKEN_URL", "<token_endpoint>"},
        {:user_url, "USER_URL", "<user_info_endpoint>"}
      ]
      |> Enum.reject(fn {field, _, _} -> Keyword.has_key?(options, field) end)
      |> Enum.map_join("\n", fn {_, suffix, placeholder} ->
        "  #{env_prefix}_#{suffix}=#{placeholder}"
      end)
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
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Oauth2 do
    @shortdoc "Adds a generic OAuth2 authentication strategy to your user resource"
    @moduledoc @shortdoc
    use Mix.Task

    def run(_argv) do
      Mix.shell().error("The task 'ash_authentication.add_strategy.oauth2' requires igniter.")
      exit({:shutdown, 1})
    end
  end
end
