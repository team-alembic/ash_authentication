# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddAddOn do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_add_on audit_log"

    @shortdoc "Adds the provided add-on to your user resource"

    @add_ons [
      audit_log: "Track authentication events for security and compliance."
    ]

    @add_on_explanation Enum.map_join(@add_ons, "\n", fn {name, description} ->
                          "  * `#{name}` - #{description}"
                        end)

    @add_on_names @add_ons |> Keyword.keys() |> Enum.map(&to_string/1)

    @add_on_options [
                      audit_log: [
                        "audit-log":
                          "The audit log resource name. Defaults to `<domain>.AuditLog`.",
                        "include-fields":
                          "Comma-separated list of sensitive fields to include in audit logs.",
                        "exclude-strategies":
                          "Comma-separated list of authentication strategies to exclude from logging.",
                        "exclude-actions":
                          "Comma-separated list of actions to exclude from logging."
                      ]
                    ]
                    |> Enum.reduce("", fn {add_on, opts}, result ->
                      add_on_title =
                        add_on
                        |> to_string()
                        |> String.split("_")
                        |> Enum.map_join(" ", &String.capitalize/1)

                      result <>
                        "## #{add_on_title} options\n\n" <>
                        Enum.map_join(opts, "\n", &"  - `#{elem(&1, 0)}` - #{elem(&1, 1)}")
                    end)

    @moduledoc """
    #{@shortdoc}

    This task will add the provided add-on to your user resource and set up any required supporting resources.

    The following add-ons are available:

    #{@add_on_explanation}

    ## Example

    ```bash
    #{@example}
    ```

    ## Global options

    * `--user`, `-u` -  The user resource. Defaults to `YourApp.Accounts.User`

    #{@add_on_options}
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
      add_on_list = igniter.args.positional[:add_on] || []
      add_on = if is_list(add_on_list), do: List.first(add_on_list), else: add_on_list
      default_user = Igniter.Project.Module.module_name(igniter, "Accounts.User")

      options =
        igniter.args.options
        |> Keyword.update(:user, default_user, &Igniter.Project.Module.parse/1)

      if add_on not in @add_on_names do
        Mix.shell().error("""
        Invalid add-on provided: `#{add_on || "none"}`

        Not all add-ons can be installed using `ash_authentication.add_add_on` yet.
        Want to see an add-on added? Open an issue (or even better, a PR!) on GitHub.

        See a list of add-ons and how to install them here:

        https://hexdocs.pm/ash_authentication/get-started.html

        Available Add-ons:

        #{@add_on_explanation}
        """)

        exit({:shutdown, 1})
      end

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          case add_on do
            "audit_log" ->
              igniter
              |> audit_log(options)
              |> Ash.Igniter.codegen("add_audit_log")
          end

        {false, igniter} ->
          Igniter.add_issue(igniter, """
          User module #{inspect(options[:user])} was not found.

          Perhaps you have not yet installed ash_authentication?
          """)
      end
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
