# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy password"

    @shortdoc "Adds the provided strategy or strategies to your user resource"

    @strategies [
      password: "Register and sign in with a username/email and a password.",
      magic_link: "Register and sign in with a magic link, sent via email to the user.",
      api_key: "Sign in with an API key.",
      totp: "Authenticate with a time-based one-time password (TOTP).",
      recovery_code: "Authenticate with one-time recovery codes as a 2FA fallback."
    ]

    @strategy_explanation Enum.map_join(@strategies, "\n", fn {name, description} ->
                            "  * `#{name}` - #{description}"
                          end)

    @strategy_names @strategies |> Keyword.keys() |> Enum.map(&to_string/1)

    @strategy_tasks %{
      "password" => "ash_authentication.add_strategy.password",
      "magic_link" => "ash_authentication.add_strategy.magic_link",
      "api_key" => "ash_authentication.add_strategy.api_key",
      "totp" => "ash_authentication.add_strategy.totp",
      "recovery_code" => "ash_authentication.add_strategy.recovery_code"
    }

    @moduledoc """
    #{@shortdoc}

    This task will add the provided strategy or strategies to your user resource.

    The following strategies are available. For all others, see the relevant documentation for setup

    #{@strategy_explanation}

    Each strategy can also be added directly with its own task:

      * `mix ash_authentication.add_strategy.password`
      * `mix ash_authentication.add_strategy.magic_link`
      * `mix ash_authentication.add_strategy.api_key`
      * `mix ash_authentication.add_strategy.totp`

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` -  The user resource. Defaults to `YourApp.Accounts.User`
    * `--identity-field`, `-i` - The field on the user resource that will be used to identify
      the user. Defaults to `email`

    ## Password options

      - `hash-provider` - The hash provider to use, either `bcrypt` or `argon2`.  Defaults to `bcrypt`.

    ## TOTP options

      - `--mode`, `-m` - Either `primary` or `2fa`. Defaults to `2fa`.
      - `--name`, `-n` - The name of the TOTP strategy. Defaults to `totp`.
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [
          strategies: [rest: true]
        ],
        composes: Map.values(@strategy_tasks),
        schema: [
          accounts: :string,
          user: :string,
          identity_field: :string,
          api_key: :string,
          hash_provider: :string,
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
          identity_field: "email"
        ]
      }
    end

    def igniter(igniter) do
      strategies = igniter.args.positional[:strategies] || []

      invalid_strategy = Enum.find(strategies, &(&1 not in @strategy_names))

      if invalid_strategy do
        Mix.shell().error("""
        Invalid strategy provided: `#{invalid_strategy}`

        Not all strategies can be installed using `ash_authentication.add_strategy` yet.
        Want to see a strategy added? Open an issue (or even better, a PR!) on GitHub.

        See a list of strategies and how to install them here:

        https://hexdocs.pm/ash_authentication/get-started.html

        Available Strategies:

        #{@strategy_explanation}
        """)

        exit({:shutdown, 1})
      end

      argv = igniter.args.argv_flags

      Enum.reduce(strategies, igniter, fn strategy, igniter ->
        Igniter.compose_task(igniter, @strategy_tasks[strategy], argv)
      end)
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddStrategy do
    @shortdoc "Adds the provided strategy or strategies to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_strategy' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
