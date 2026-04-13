# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Github do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy.github"

    @shortdoc "Adds GitHub OAuth authentication to your user resource"

    @moduledoc """
    #{@shortdoc}

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` - The user resource. Defaults to `YourApp.Accounts.User`
    * `--accounts`, `-a` - The accounts domain. Defaults to `YourApp.Accounts`
    * `--identity-field`, `-i` - The field used to identify the user. Defaults to `email`
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [],
        composes: [],
        schema: [
          accounts: :string,
          user: :string,
          identity_field: :string
        ],
        aliases: [
          a: :accounts,
          u: :user,
          i: :identity_field
        ],
        defaults: [
          identity_field: "email"
        ]
      }
    end

    def igniter(igniter) do
      options = parse_options(igniter)

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          identity_resource =
            Module.concat(AshAuthentication.Igniter.parent_module(options[:user]), UserIdentity)

          secrets_module = Igniter.Project.Module.module_name(igniter, "Secrets")

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
            :github,
            identity_field: options[:identity_field],
            identity_resource: identity_resource
          )
          |> AshAuthentication.Igniter.add_oauth_secrets(
            secrets_module,
            options[:user],
            :github,
            [
              {:client_id, "GITHUB_CLIENT_ID"},
              {:client_secret, "GITHUB_CLIENT_SECRET"},
              {:redirect_uri, "GITHUB_REDIRECT_URI"}
            ]
          )
          |> AshAuthentication.Igniter.add_new_strategy(options[:user], :github, :github, """
          github :github do
            client_id #{inspect(secrets_module)}
            client_secret #{inspect(secrets_module)}
            redirect_uri #{inspect(secrets_module)}
            identity_resource #{inspect(identity_resource)}
          end
          """)
          |> AshAuthentication.Igniter.codegen_for_strategy(:github)
          |> Igniter.add_notice("""
          GitHub OAuth setup:

          1. Go to https://github.com/settings/developers
          2. Click "New OAuth App"
          3. Set the callback URL to: http://localhost:4000/auth/github/callback

          Set these environment variables:
            GITHUB_CLIENT_ID=<your_client_id>
            GITHUB_CLIENT_SECRET=<your_client_secret>
            GITHUB_REDIRECT_URI=http://localhost:4000/auth
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
      |> Keyword.put_new_lazy(:user, fn ->
        Module.concat(options[:accounts], User)
      end)
      |> Keyword.update(:identity_field, :email, &String.to_atom/1)
      |> Keyword.update!(:accounts, &AshAuthentication.Igniter.maybe_parse_module/1)
      |> Keyword.update!(:user, &AshAuthentication.Igniter.maybe_parse_module/1)
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Github do
    @shortdoc "Adds GitHub OAuth authentication to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_strategy.github' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
