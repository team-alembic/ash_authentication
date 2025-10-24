# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.Gen.AddOn.AuditLog do
    use Igniter.Mix.Task

    @example "mix ash_authentication.gen.add_on.audit_log"
    @shortdoc "Adds the audit-log add-on to your user resource"

    @moduledoc """
    #{@shortdoc}

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` - The user resource. Defaults to `YourApp.Accounts.User`
    * `--audit-log`, `-a` - The audit log resource name. Defaults to `YourApp.Accounts.User`.
    * `--include-strategies` - Comma-separated list of strategy names to perform audit logging for. `:*` for all. Defaults to `:*`.
    * `--include-actions` - Comma-separated list of action names to perform audit logging for. `:*` for all. Defaults to `:*`.
    * `--include-fields` - Comma-separated list of sensitive attribute or argument names to include in the audit log.
    * `--exclude-strategies` - Comma-separated list of strategy names to explicitly exclude from audit logging.
    * `--exclude-actions` - Comma-separated list of action names to explicitly exclude from audit logging.
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [
          add_on: []
        ],
        schema: [
          user: :string,
          audit_log: :string,
          include_strategies: :csv,
          include_actions: :csv,
          include_fields: :csv,
          exclude_strategies: :csv,
          exclude_actions: :csv
        ],
        aliases: [
          u: :user,
          a: :audit_log
        ]
      }
    end

    def igniter(igniter) do
      default_user = Igniter.Project.Module.module_name(igniter, "Accounts.User")

      options =
        igniter.args.options
        |> Keyword.update(:user, default_user, &Igniter.Project.Module.parse/1)

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          igniter
          |> generate(options)
          |> Ash.Igniter.codegen("add_audit_log")

        {false, igniter} ->
          Igniter.add_issue(igniter, """
          User module #{inspect(options[:user])} was not found.

          Perhaps you have not yet installed ash_authentication?
          """)
      end
    end

    defp generate(igniter, options) do
      igniter
      |> generate_audit_log_resource(options)
    end

    defp generate_audit_log_resource(igniter, options) do
      audit_log =
        if options[:audit_log] do
          options[:audit_log]
        else
          options[:user]
          |> Module.split()
          |> :list.droplast()
          |> Enum.concat(["AuditLog"])
          |> Module.concat()
        end

      igniter
      |> Igniter.compose_task(Mix.Tasks.AshAuthentication.Gen.Resource.AuditLog, [audit_log])
    end

    defp audit_log(igniter, options) do
      audit_log_resource =
        if audit_log = options[:audit_log] do
          Igniter.Project.Module.parse(audit_log)
        else
          options[:user]
          |> Module.split()
          |> :lists.droplast()
          |> Enum.concat([AuditLog])
          |> Module.concat()
        end

      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, audit_log_resource)

      if exists? do
        Igniter.add_issue(
          igniter,
          """
          Audit log resource already exists: #{inspect(audit_log_resource)}.
          Please use the `--audit-log` option to provide a different name.
          """
        )
      else
        otp_app = Igniter.Project.Application.app_name(igniter)

        extensions =
          cond do
            Code.ensure_loaded?(AshPostgres.DataLayer) ->
              "postgres"

            Code.ensure_loaded?(AshSqlite.DataLayer) ->
              "sqlite"

            true ->
              nil
          end

        domain =
          options[:user]
          |> Module.split()
          |> :lists.droplast()
          |> Module.concat()

        {igniter, resource_args, _repo} = data_layer_args(igniter, options)

        resource_args =
          if extensions do
            resource_args ++ ["--extend", extensions, "--domain", inspect(domain)]
          else
            resource_args ++ ["--domain", inspect(domain)]
          end

        igniter
        |> Igniter.compose_task("ash.gen.resource", [
          inspect(audit_log_resource),
          "--default-actions",
          "read"
          | resource_args
        ])
        |> Igniter.compose_task("ash.extend", [
          inspect(audit_log_resource),
          "AshAuthentication.AuditLogResource"
        ])
        |> add_audit_log_add_on(options[:user], audit_log_resource, options)
        |> ensure_supervisor(otp_app)
      end
    end

    defp add_audit_log_add_on(igniter, user_resource, audit_log_resource, options) do
      include_fields = options[:include_fields] || []
      exclude_strategies = options[:exclude_strategies] || []
      exclude_actions = options[:exclude_actions] || []

      include_fields_config =
        if include_fields != [] do
          fields = Enum.map_join(include_fields, ", ", &":#{&1}")
          "include_fields [#{fields}]"
        else
          ""
        end

      exclude_strategies_config =
        if exclude_strategies != [] do
          strategies = Enum.map_join(exclude_strategies, ", ", &":#{&1}")
          "exclude_strategies [#{strategies}]"
        else
          ""
        end

      exclude_actions_config =
        if exclude_actions != [] do
          actions = Enum.map_join(exclude_actions, ", ", &":#{&1}")
          "exclude_actions [#{actions}]"
        else
          ""
        end

      configs =
        [include_fields_config, exclude_strategies_config, exclude_actions_config]
        |> Enum.reject(&(&1 == ""))
        |> Enum.join("\n    ")

      configs_section = if configs != "", do: "\n    #{configs}", else: ""

      AshAuthentication.Igniter.add_new_add_on(
        igniter,
        user_resource,
        :audit_log,
        nil,
        """
        audit_log do
          audit_log_resource #{inspect(audit_log_resource)}#{configs_section}
        end
        """
      )
    end

    defp ensure_supervisor(igniter, otp_app) do
      # Check if AshAuthentication.Supervisor is already in the supervision tree
      Igniter.Project.Application.add_new_child(
        igniter,
        {AshAuthentication.Supervisor, otp_app: otp_app},
        after: fn _ -> true end
      )
    end

    cond do
      Code.ensure_loaded?(AshPostgres.Igniter) ->
        def data_layer_args(igniter, opts) do
          {igniter, repo} =
            AshPostgres.Igniter.select_repo(igniter, generate?: false, yes: opts[:yes])

          {igniter, ["--repo", inspect(repo)], repo}
        end

      Code.ensure_loaded?(AshSqlite.Igniter) ->
        def data_layer_args(igniter, opts) do
          {igniter, repo} =
            AshSqlite.Igniter.select_repo(igniter, generate?: false, yes: opts[:yes])

          {igniter, ["--repo", inspect(repo)], repo}
        end

      true ->
        def data_layer_args(igniter, _) do
          {igniter, [], nil}
        end
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddAddOn do
    @shortdoc "Adds the provided add-on to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_add_on' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
