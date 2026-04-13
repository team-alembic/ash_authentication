# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Slack do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy.slack"

    @shortdoc "Adds Slack OAuth authentication to your user resource"

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
    * `--team-id` - Optional Slack team ID to restrict sign-in to a specific workspace
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [],
        composes: [],
        schema: [accounts: :string, user: :string, identity_field: :string, team_id: :string],
        aliases: [a: :accounts, u: :user, i: :identity_field],
        defaults: [identity_field: "email"]
      }
    end

    def igniter(igniter) do
      options = parse_options(igniter)

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          identity_resource =
            Module.concat(AshAuthentication.Igniter.parent_module(options[:user]), UserIdentity)

          secrets_module = Igniter.Project.Module.module_name(igniter, "Secrets")

          secret_pairs = [
            {:client_id, "SLACK_CLIENT_ID"},
            {:client_secret, "SLACK_CLIENT_SECRET"},
            {:redirect_uri, "SLACK_REDIRECT_URI"}
          ]

          secret_pairs =
            if options[:team_id] do
              secret_pairs ++ [{:team_id, "SLACK_TEAM_ID"}]
            else
              secret_pairs
            end

          team_id_line =
            if options[:team_id] do
              "team_id #{inspect(secrets_module)}"
            else
              ""
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
            :slack,
            identity_field: options[:identity_field],
            identity_resource: identity_resource
          )
          |> AshAuthentication.Igniter.add_oauth_secrets(
            secrets_module,
            options[:user],
            :slack,
            secret_pairs
          )
          |> AshAuthentication.Igniter.add_new_strategy(options[:user], :slack, :slack, """
          slack :slack do
            client_id #{inspect(secrets_module)}
            client_secret #{inspect(secrets_module)}
            redirect_uri #{inspect(secrets_module)}
            #{team_id_line}
            identity_resource #{inspect(identity_resource)}
          end
          """)
          |> AshAuthentication.Igniter.codegen_for_strategy(:slack)
          |> Igniter.add_notice("""
          Slack OAuth setup:

          1. Go to https://api.slack.com/apps
          2. Create a new app (or select an existing one)
          3. Under "OAuth & Permissions", add http://localhost:4000/auth/slack/callback to "Redirect URLs"

          Set these environment variables:
            SLACK_CLIENT_ID=<your_client_id>
            SLACK_CLIENT_SECRET=<your_client_secret>
            SLACK_REDIRECT_URI=http://localhost:4000/auth
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
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Slack do
    @shortdoc "Adds Slack OAuth authentication to your user resource"
    @moduledoc @shortdoc
    use Mix.Task

    def run(_argv) do
      Mix.shell().error("The task 'ash_authentication.add_strategy.slack' requires igniter.")
      exit({:shutdown, 1})
    end
  end
end
