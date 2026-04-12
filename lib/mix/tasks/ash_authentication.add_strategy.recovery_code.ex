# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.RecoveryCode do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy recovery_code"

    @shortdoc "Adds the recovery code authentication strategy"

    @moduledoc """
    #{@shortdoc}

    Creates a recovery code resource and adds the recovery code strategy
    to the user resource. Recovery codes are one-time backup codes that
    allow users to authenticate when their primary 2FA method (e.g. TOTP)
    is unavailable.

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` - The user resource. Defaults to `YourApp.Accounts.User`
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [],
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
          igniter
          |> add_recovery_code_resource(options)
          |> Ash.Igniter.codegen("add_recovery_code_auth")

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
      |> Keyword.update!(:accounts, &maybe_parse_module/1)
      |> Keyword.update!(:user, &maybe_parse_module/1)
    end

    defp maybe_parse_module(value) when is_binary(value), do: Igniter.Project.Module.parse(value)
    defp maybe_parse_module(value), do: value

    defp add_recovery_code_resource(igniter, options) do
      recovery_code_resource =
        options[:user]
        |> Module.split()
        |> :lists.droplast()
        |> Enum.concat([RecoveryCode])
        |> Module.concat()

      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, recovery_code_resource)

      if exists? do
        Igniter.add_issue(
          igniter,
          """
          Recovery code resource already exists: #{inspect(recovery_code_resource)}.
          """
        )
      else
        extensions =
          cond do
            Code.ensure_loaded?(AshPostgres.DataLayer) -> "postgres"
            Code.ensure_loaded?(AshSqlite.DataLayer) -> "sqlite"
            true -> ""
          end

        igniter
        |> Igniter.compose_task("ash.gen.resource", [
          inspect(recovery_code_resource),
          "--uuid-primary-key",
          "id",
          "--default-actions",
          "read,destroy",
          "--attribute",
          "code:string:required:sensitive",
          "--relationship",
          "belongs_to:user:#{inspect(options[:user])}:required",
          "--extend",
          extensions
        ])
        |> Ash.Resource.Igniter.add_new_action(recovery_code_resource, :create, """
        create :create do
          primary? true
          accept [:code]
        end
        """)
        |> Ash.Resource.Igniter.add_new_relationship(
          options[:user],
          :recovery_codes,
          """
          has_many :recovery_codes, #{inspect(recovery_code_resource)}
          """
        )
        |> compose_audit_log(options)
        |> Ash.Resource.Igniter.add_new_action(options[:user], :verify_with_recovery_code, """
        action :verify_with_recovery_code do
          argument :user, :struct do
            allow_nil? false
            sensitive? true
            constraints instance_of: __MODULE__
          end

          argument :code, :string do
            allow_nil? false
            sensitive? true
          end

          prepare {AshAuthentication.AddOn.AuditLog.BruteForcePreparation,
                   action_name: :verify_with_recovery_code}

          returns :term
          transaction? true
          run AshAuthentication.Strategy.RecoveryCode.VerifyAction
          touches_resources [#{inspect(recovery_code_resource)}]
          description "Verify a recovery code and return the user if valid, nil otherwise."
        end
        """)
        |> Ash.Resource.Igniter.add_new_action(options[:user], :generate_recovery_code_codes, """
        update :generate_recovery_code_codes do
          require_atomic? false
          accept []

          argument :recovery_codes, {:array, :string} do
            allow_nil? false
            sensitive? true
            default {AshAuthentication.Strategy.RecoveryCode.Actions, :generate_codes_list,
                     [12, 10, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]}
          end

          change {Ash.Resource.Change.CascadeDestroy, relationship: :recovery_codes, after_action?: false}
          change {AshAuthentication.Strategy.RecoveryCode.HashRecoveryCodesChange, hash_provider: AshAuthentication.SHA256Provider}
          change {Ash.Resource.Change.ManageRelationship,
                  argument: :recovery_codes,
                  relationship: :recovery_codes,
                  opts: [type: :create, value_is_key: :code]}

          metadata :recovery_codes, {:array, :string}, allow_nil?: false
          touches_resources [#{inspect(recovery_code_resource)}]
          description "Generate new recovery codes for the user, replacing any existing codes."
        end
        """)
        |> AshAuthentication.Igniter.add_new_strategy(
          options[:user],
          :recovery_code,
          :recovery_code,
          """
          recovery_code do
            recovery_code_resource #{inspect(recovery_code_resource)}
            brute_force_strategy {:audit_log, :audit_log}
          end
          """
        )
      end
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
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.RecoveryCode do
    @shortdoc "Adds the recovery code authentication strategy"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_strategy.recovery_code' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
