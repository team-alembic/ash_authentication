# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.Gen.Resource.AuditLog do
    use Igniter.Mix.Task

    @example "mix ash_authenticastion.gen.resource.audit_log MyApp.Accounts.AuditLog"
    @shortdoc "Adds an audit-log resource to your system"

    @moduledoc """
    #{@shortdoc}

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    All options are passed through to `mix ash.gen.resource`.
    """

    @impl Igniter.Mix.Task
    def into(_argv, _composing_task) do
      agn_info = Mix.Tasks.Ash.Gen.Resource.info([], nil)

      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [:resource],
        schema: agn_info.schema,
        aliases: agn_info.aliases
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      otp_app = Igniter.Project.Application.app_name(igniter)

      extensions =
        igniter
        |> calculate_extensions()
        |> Enum.join(",")

      opts =
        igniter.options
        |> Keyword.drop(:extend)
        |> Enum.reduce(["--extend", extensions], fn {name, value}, opts ->
          switch =
            name
            |> to_string()
            |> String.replace("_", "-")
            |> then(&"--#{&1}")

          value =
            if is_list(value) do
              Enum.join(value, ",")
            else
              to_string(value)
            end

          [switch, value]
        end)

      igniter
      |> Igniter.compose_task("ash.gen.resource", [igniter.positional.resource | opts])
    end

    defp calculate_extensions(igniter) do
      extensions = igniter.options[:extend] || []

      extensions =
        if "postgres" not in extensions and "sqlite" not in extensions do
          extensions ++ detect_data_layer()
        else
          extensions
        end

      extensions ++ [AshAuthentication.AuditLogResource]
    end

    defp detect_data_layer do
      cond do
        Code.ensure_loaded?(AshPostgres.DataLayer) ->
          ["postgres"]

        Code.ensure_loaded?(AshSqlite.DataLayer) ->
          ["sqlite"]

        true ->
          []
      end
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.Gen.Resource.AuditLog do
    @shortdoc "Adds an audit-log resource to your system"
    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.gen.resource.audit_log' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
