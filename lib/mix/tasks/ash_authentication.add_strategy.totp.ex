# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Totp do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy.totp --mode 2fa"

    @shortdoc "Adds TOTP authentication to your user resource"

    @moduledoc """
    #{@shortdoc}

    TOTP can be used in two modes:

      * `2fa` - As a second factor after password authentication (default)
      * `primary` - As the primary authentication method (passwordless)

    Both modes use an audit log add-on for brute force protection, which will be
    created automatically if one doesn't already exist.

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` - The user resource. Defaults to `YourApp.Accounts.User`
    * `--identity-field`, `-i` - The field on the user resource that will be used to identify
      the user. Defaults to `email`
    * `--mode`, `-m` - Either `primary` or `2fa`. Defaults to `2fa`.
    * `--name`, `-n` - The name of the TOTP strategy. Defaults to `totp`.
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [],
        composes: [
          "ash_authentication.add_add_on.audit_log"
        ],
        schema: [
          accounts: :string,
          user: :string,
          identity_field: :string,
          mode: :string,
          name: :string
        ],
        aliases: [
          a: :accounts,
          u: :user,
          i: :identity_field,
          m: :mode,
          n: :name
        ],
        defaults: [
          identity_field: "email",
          mode: "2fa",
          name: "totp"
        ]
      }
    end

    def igniter(igniter) do
      options = parse_options(igniter)

      if options[:mode] not in [:primary, :"2fa"] do
        Mix.shell().error("""
        Invalid mode: #{inspect(options[:mode])}

        Available modes:

          * `2fa` - Use TOTP as a second factor after password authentication
          * `primary` - Use TOTP as the primary authentication method
        """)

        exit({:shutdown, 1})
      end

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          igniter
          |> totp(options)
          |> Ash.Igniter.codegen("add_totp_auth")

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
      |> Keyword.update(:mode, :"2fa", &String.to_atom/1)
      |> Keyword.update(:name, :totp, &String.to_atom/1)
      |> Keyword.update!(:accounts, &AshAuthentication.Igniter.maybe_parse_module/1)
      |> Keyword.update!(:user, &AshAuthentication.Igniter.maybe_parse_module/1)
    end

    defp totp(igniter, options) do
      igniter
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], :totp_secret, """
      attribute :totp_secret, :binary do
        allow_nil? true
        sensitive? true
        public? false
      end
      """)
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], :last_totp_at, """
      attribute :last_totp_at, :datetime do
        allow_nil? true
        sensitive? true
        public? false
      end
      """)
      |> AshAuthentication.Igniter.ensure_identity(options[:user], options[:identity_field])
      |> compose_audit_log(options)
      |> add_totp_actions(options)
      |> AshAuthentication.Igniter.add_new_strategy(
        options[:user],
        :totp,
        options[:name],
        build_strategy_config(options)
      )
    end

    defp add_totp_actions(igniter, options) do
      name = options[:name]
      setup_name = :"setup_with_#{name}"
      confirm_name = :"confirm_setup_with_#{name}"
      verify_name = :"verify_with_#{name}"

      igniter
      |> Ash.Resource.Igniter.add_new_action(options[:user], setup_name, """
      update #{inspect(setup_name)} do
        require_atomic? false
        accept []

        change AshAuthentication.Strategy.Totp.GeneratePendingSetupChange

        metadata :setup_token, :string, allow_nil?: false
        metadata :totp_url, :string, allow_nil?: false
        description "Generate a pending TOTP secret and return a setup token. Use the confirm_setup action to activate."
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], confirm_name, """
      update #{inspect(confirm_name)} do
        require_atomic? false
        accept []

        argument :setup_token, :string do
          allow_nil? false
          sensitive? true
          description "The setup token from the setup action."
        end

        argument :code, :string do
          allow_nil? false
          description "The TOTP code to verify."
        end

        change {AshAuthentication.Strategy.Totp.AuditLogChange,
                action_name: #{inspect(confirm_name)}}
        change AshAuthentication.Strategy.Totp.ConfirmSetupChange

        description "Confirm TOTP setup by verifying a code and activating the secret."
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], verify_name, """
      action #{inspect(verify_name)} do
        argument :user, :struct do
          allow_nil? false
          sensitive? true
          constraints instance_of: __MODULE__
        end

        argument :code, :string do
          allow_nil? false
          description "The TOTP code to verify."
        end

        prepare {AshAuthentication.Strategy.Totp.AuditLogPreparation,
                 action_name: #{inspect(verify_name)}}

        returns :boolean
        transaction? true
        run AshAuthentication.Strategy.Totp.VerifyAction
        description "Is the provided TOTP code valid for the user?"
      end
      """)
    end

    defp build_strategy_config(options) do
      sign_in_line =
        if options[:mode] == :primary do
          "\n    sign_in_enabled? true"
        else
          ""
        end

      """
      totp #{inspect(options[:name])} do
        identity_field #{inspect(options[:identity_field])}#{sign_in_line}
        confirm_setup_enabled? true
        brute_force_strategy {:audit_log, :audit_log}
      end
      """
    end

    defp compose_audit_log(igniter, options) do
      {igniter, has_audit_log?} =
        AshAuthentication.Igniter.defines_add_on(igniter, options[:user], :audit_log, nil)

      if has_audit_log? do
        igniter
      else
        Igniter.compose_task(
          igniter,
          "ash_authentication.add_add_on.audit_log",
          ["--user", inspect(options[:user])]
        )
      end
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Totp do
    @shortdoc "Adds TOTP authentication to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_strategy.totp' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
