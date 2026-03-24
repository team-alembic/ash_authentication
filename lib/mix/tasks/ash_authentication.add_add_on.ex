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
      audit_log: "Track authentication events for security and compliance.",
      confirmation: "Confirm new users via email."
    ]

    @add_on_explanation Enum.map_join(@add_ons, "\n", fn {name, description} ->
                          "  * `#{name}` - #{description}"
                        end)

    @add_on_names @add_ons |> Keyword.keys() |> Enum.map(&to_string/1)

    @add_on_tasks %{
      "audit_log" => "ash_authentication.add_add_on.audit_log",
      "confirmation" => "ash_authentication.add_add_on.confirmation"
    }

    @moduledoc """
    #{@shortdoc}

    This task will add the provided add-on to your user resource and set up any required supporting resources.

    The following add-ons are available:

    #{@add_on_explanation}

    Each add-on can also be added directly with its own task:

      * `mix ash_authentication.add_add_on.audit_log`
      * `mix ash_authentication.add_add_on.confirmation`

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` -  The user resource. Defaults to `YourApp.Accounts.User`

    ## Audit Log options

      - `--audit-log` - The audit log resource name. Defaults to `<domain>.AuditLog`.
      - `--include-fields` - Comma-separated list of sensitive fields to include in audit logs.
      - `--exclude-strategies` - Comma-separated list of authentication strategies to exclude from logging.
      - `--exclude-actions` - Comma-separated list of actions to exclude from logging.
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
        composes: Map.values(@add_on_tasks),
        schema: [
          user: :string,
          identity_field: :string,
          audit_log: :string,
          include_fields: :csv,
          exclude_strategies: :csv,
          exclude_actions: :csv
        ],
        aliases: [
          u: :user,
          a: :audit_log,
          i: :identity_field
        ]
      }
    end

    def igniter(igniter) do
      add_on_list = igniter.args.positional[:add_on] || []
      add_on = if is_list(add_on_list), do: List.first(add_on_list), else: add_on_list

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

      Igniter.compose_task(igniter, @add_on_tasks[add_on], igniter.args.argv_flags)
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
