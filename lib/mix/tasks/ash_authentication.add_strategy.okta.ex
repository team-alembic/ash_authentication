# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Okta do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy.okta"

    @shortdoc "Adds Okta OIDC authentication to your user resource"

    @moduledoc """
    #{@shortdoc}

    Okta requires you to point at a specific authorization server. The recommended
    setting is `https://YOUR_OKTA_DOMAIN/oauth2/default` (the built-in `default`
    Custom Authorization Server). Configure it via the `OKTA_BASE_URL`
    environment variable, or pass `--base-url` to bake it directly into the DSL.

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
        positional: [],
        composes: [],
        schema: [
          accounts: :string,
          user: :string,
          identity_field: :string,
          base_url: :string
        ],
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
            {:client_id, "OKTA_CLIENT_ID"},
            {:client_secret, "OKTA_CLIENT_SECRET"},
            {:redirect_uri, "OKTA_REDIRECT_URI"}
          ]

          {base_url_line, secret_pairs} =
            if options[:base_url] do
              {"base_url \"#{options[:base_url]}\"", secret_pairs}
            else
              {"base_url #{inspect(secrets_module)}",
               secret_pairs ++ [{:base_url, "OKTA_BASE_URL"}]}
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
            :okta,
            identity_field: options[:identity_field],
            identity_resource: identity_resource
          )
          |> AshAuthentication.Igniter.add_oauth_secrets(
            secrets_module,
            options[:user],
            :okta,
            secret_pairs
          )
          |> AshAuthentication.Igniter.add_new_strategy(
            options[:user],
            :okta,
            :okta,
            """
            okta :okta do
              client_id #{inspect(secrets_module)}
              client_secret #{inspect(secrets_module)}
              redirect_uri #{inspect(secrets_module)}
              #{base_url_line}
              identity_resource #{inspect(identity_resource)}
            end
            """
          )
          |> AshAuthentication.Igniter.codegen_for_strategy(:okta)
          |> Igniter.add_notice("""
          Okta OIDC setup:

          1. In the Okta Admin Console, go to Applications > Applications
          2. Click "Create App Integration", choose "OIDC - OpenID Connect" and
             "Web Application"
          3. Under "Sign-in redirect URIs", add the per-strategy callback URL:
             http://localhost:4000/auth/user/okta/callback
          4. Copy the Client ID and Client secret from the General tab

          Set these environment variables:
            OKTA_CLIENT_ID=<your_client_id>
            OKTA_CLIENT_SECRET=<your_client_secret>
            OKTA_REDIRECT_URI=http://localhost:4000/auth
          #{unless options[:base_url], do: "  OKTA_BASE_URL=https://YOUR_OKTA_DOMAIN/oauth2/default"}
          Note: OKTA_REDIRECT_URI is the *base* AuthPlug URL (no trailing
          provider path). AshAuthentication appends the provider/strategy
          segments itself, so the full callback URL Okta should redirect to
          is the one in step 3 above.

          The `default` in OKTA_BASE_URL refers to the built-in Custom
          Authorization Server. To use a different one, replace `default` with
          its ID (Security > API > Authorization Servers).
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
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Okta do
    @shortdoc "Adds Okta OIDC authentication to your user resource"
    @moduledoc @shortdoc
    use Mix.Task

    def run(_argv) do
      Mix.shell().error("The task 'ash_authentication.add_strategy.okta' requires igniter.")
      exit({:shutdown, 1})
    end
  end
end
