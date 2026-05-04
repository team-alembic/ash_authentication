# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.DynamicOidc do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy.dynamic_oidc"

    @shortdoc "Adds a data-driven OIDC strategy + OidcConnection resource"

    @moduledoc """
    #{@shortdoc}

    Generates a `OidcConnection` resource (in your accounts namespace) for
    storing per-tenant/per-customer OIDC client configuration, then wires a
    `dynamic_oidc :sso` strategy into your user resource that looks up the
    connection at request time.

    The shape of the generated connection resource includes `base_url`,
    `client_id`, `client_secret` (sensitive), `display_name`, and `icon_url`
    string attributes plus a default bypass policy for AshAuthentication
    interactions. You're expected to add multitenancy and any custom
    write-side policies yourself.

    See the `AshAuthentication.Strategy.DynamicOidc` and
    `AshAuthentication.OidcConnection` moduledocs for runtime details.

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

      * `--user`, `-u` — The user resource. Defaults to `YourApp.Accounts.User`.
      * `--accounts`, `-a` — The accounts domain. Defaults to `YourApp.Accounts`.
      * `--identity-field`, `-i` — The user attribute used to identify users.
        Defaults to `email`.
      * `--connection`, `-c` — The OidcConnection resource name. Defaults to
        `<accounts>.OidcConnection`.
      * `--name`, `-n` — The strategy name. Defaults to `sso`.
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
          connection: :string,
          name: :string
        ],
        aliases: [a: :accounts, u: :user, i: :identity_field, c: :connection, n: :name],
        defaults: [identity_field: "email", name: "sso"]
      }
    end

    # sobelow_skip ["DOS.BinToAtom"]
    def igniter(igniter) do
      options = parse_options(igniter)
      strategy_name = String.to_atom(options[:name])

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          identity_resource =
            Module.concat(AshAuthentication.Igniter.parent_module(options[:user]), UserIdentity)

          connection_resource = connection_module(options)

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
          |> generate_connection_resource(connection_resource, options)
          |> AshAuthentication.Igniter.add_oauth_register_action(
            options[:user],
            strategy_name,
            identity_field: options[:identity_field],
            identity_resource: identity_resource
          )
          |> AshAuthentication.Igniter.add_new_strategy(
            options[:user],
            :dynamic_oidc,
            strategy_name,
            """
            dynamic_oidc :#{strategy_name} do
              connection_resource #{inspect(connection_resource)}
              identity_resource #{inspect(identity_resource)}
              redirect_uri "http://localhost:4000/auth"
            end
            """
          )
          |> AshAuthentication.Igniter.codegen_for_strategy(strategy_name)
          |> Igniter.add_notice("""
          Dynamic OIDC strategy "#{strategy_name}" setup:

          1. Populate #{inspect(connection_resource)} with one row per
             customer / tenant. Each row needs `base_url`, `client_id`, and
             `client_secret` from that customer's OIDC IdP (Okta, Entra ID,
             Auth0, etc.). Optionally set `display_name` and `icon_url` for
             the sign-in UI.
          2. Each customer's IdP admin should register the following callback
             URL in their app integration:
               http://your-app.example/auth/user/#{strategy_name}/callback
          3. Set Ash tenant upstream of the auth router (e.g. from subdomain
             in a Phoenix plug) so the strategy scopes connection lookups
             correctly.

          Encrypt `client_secret` at rest in production — see `ash_cloak`.
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

    defp connection_module(options) do
      if connection = options[:connection] do
        Igniter.Project.Module.parse(connection)
      else
        Module.concat(options[:accounts], OidcConnection)
      end
    end

    defp generate_connection_resource(igniter, connection_resource, options) do
      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, connection_resource)

      if exists? do
        Igniter.add_issue(
          igniter,
          """
          OidcConnection resource already exists: #{inspect(connection_resource)}.
          Pass `--connection` with a different module name, or remove the existing one.
          """
        )
      else
        extensions =
          cond do
            Code.ensure_loaded?(AshPostgres.DataLayer) ->
              "Ash.Policy.Authorizer,postgres"

            Code.ensure_loaded?(AshSqlite.DataLayer) ->
              "Ash.Policy.Authorizer,sqlite"

            true ->
              "Ash.Policy.Authorizer"
          end

        igniter
        |> Igniter.compose_task("ash.gen.resource", [
          inspect(connection_resource),
          "--default-actions",
          "create,read,update,destroy",
          "--extend",
          extensions
        ])
        |> Igniter.Project.Module.find_and_update_module!(connection_resource, fn zipper ->
          {:ok,
           Igniter.Code.Common.add_code(zipper, """

           use Ash.Resource,
             extensions: [AshAuthentication.OidcConnection]

           oidc_connection do
             domain #{inspect(options[:accounts])}
           end
           """)}
        end)
        |> Ash.Resource.Igniter.add_bypass(
          connection_resource,
          quote do
            AshAuthentication.Checks.AshAuthenticationInteraction
          end,
          quote do
            authorize_if always()
          end
        )
      end
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.DynamicOidc do
    @shortdoc "Adds a data-driven OIDC strategy + OidcConnection resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_strategy.dynamic_oidc' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
