# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Apple do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy.apple"

    @shortdoc "Adds Apple Sign In authentication to your user resource"

    @moduledoc """
    #{@shortdoc}

    Apple Sign In uses a private key for authentication instead of a client secret.
    You will need to generate a key in the Apple Developer portal.

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
        schema: [accounts: :string, user: :string, identity_field: :string],
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
            :apple,
            identity_field: options[:identity_field],
            identity_resource: identity_resource
          )
          |> AshAuthentication.Igniter.add_oauth_secrets(secrets_module, options[:user], :apple, [
            {:client_id, "APPLE_CLIENT_ID"},
            {:redirect_uri, "APPLE_REDIRECT_URI"},
            {:team_id, "APPLE_TEAM_ID"},
            {:private_key_id, "APPLE_PRIVATE_KEY_ID"},
            {:private_key_path, "APPLE_PRIVATE_KEY_PATH"}
          ])
          |> AshAuthentication.Igniter.add_new_strategy(options[:user], :apple, :apple, """
          apple :apple do
            client_id #{inspect(secrets_module)}
            redirect_uri #{inspect(secrets_module)}
            team_id #{inspect(secrets_module)}
            private_key_id #{inspect(secrets_module)}
            private_key_path #{inspect(secrets_module)}
            identity_resource #{inspect(identity_resource)}
          end
          """)
          |> AshAuthentication.Igniter.codegen_for_strategy(:apple)
          |> Igniter.add_notice("""
          Apple Sign In setup:

          1. Go to https://developer.apple.com/account/resources/identifiers/list/serviceId
          2. Register a Services ID (this is your client_id)
          3. Enable "Sign In with Apple" and configure the return URL:
             http://localhost:4000/auth/apple/callback
          4. Create a key at https://developer.apple.com/account/resources/authkeys/list
             - Enable "Sign In with Apple"
             - Download the .p8 key file

          Set these environment variables:
            APPLE_CLIENT_ID=<your_services_id>
            APPLE_REDIRECT_URI=http://localhost:4000/auth
            APPLE_TEAM_ID=<your_team_id>
            APPLE_PRIVATE_KEY_ID=<your_key_id>
            APPLE_PRIVATE_KEY_PATH=<path_to_your_.p8_file>
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
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Apple do
    @shortdoc "Adds Apple Sign In authentication to your user resource"
    @moduledoc @shortdoc
    use Mix.Task

    def run(_argv) do
      Mix.shell().error("The task 'ash_authentication.add_strategy.apple' requires igniter.")
      exit({:shutdown, 1})
    end
  end
end
