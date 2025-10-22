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
      api_key: "Sign in with an API key."
    ]

    @strategy_explanation Enum.map_join(@strategies, "\n", fn {name, description} ->
                            "  * `#{name}` - #{description}"
                          end)

    @strategy_names @strategies |> Keyword.keys() |> Enum.map(&to_string/1)

    @strategy_options [
                        password: [
                          "hash-provider":
                            "The hash provider to use, either `bcrypt` or `argon2`.  Defaults to `bcrypt`."
                        ]
                      ]
                      |> Enum.reduce("", fn {strategy, opts}, result ->
                        strategy =
                          strategy
                          |> to_string()
                          |> String.capitalize()

                        result <>
                          "## #{strategy} options\n\n" <>
                          Enum.map_join(opts, "\n", &"  - `#{elem(&1, 0)}` - #{elem(&1, 1)}")
                      end)

    @moduledoc """
    #{@shortdoc}

    This task will add the provided strategy or strategies to your user resource.

    The following strategies are available. For all others, see the relevant documentation for setup

    #{@strategy_explanation}

    ## Example

    ```bash
    #{@example}
    ```

    ## Global options

    * `--user`, `-u` -  The user resource. Defaults to `YourApp.Accounts.User`
    * `--identity-field`, `-i` - The field on the user resource that will be used to identify
      the user. Defaults to `email`

    #{@strategy_options}
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        # A list of environments that this should be installed in, only relevant if this is an installer.
        only: nil,
        # a list of positional arguments, i.e `[:file]`
        positional: [
          strategies: [rest: true]
        ],
        schema: [
          user: :string,
          identity_field: :string,
          api_key: :string,
          hash_provider: :string
        ],
        aliases: [
          u: :user,
          a: :api_key,
          i: :identity_field
        ],
        defaults: [
          identity_field: "email"
        ]
      }
    end

    def igniter(igniter) do
      strategies = igniter.args.positional[:strategies] || []
      default_user = Igniter.Project.Module.module_name(igniter, "Accounts.User")

      options =
        igniter.args.options
        |> Keyword.update(:identity_field, :email, &String.to_atom/1)
        |> Keyword.update(:user, default_user, &Igniter.Project.Module.parse/1)

      if invalid_strategy = Enum.find(strategies, &(&1 not in @strategy_names)) do
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

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          Enum.reduce(strategies, igniter, fn
            "password", igniter ->
              options =
                options
                |> Keyword.take([:hash_provider, :user, :identity_field])
                |> Enum.flat_map(fn
                  {:hash_provider, provider} -> ["--hash-provider", provider]
                  {:user, user} -> ["--user", inspect(user)]
                  {:identity_field, field} -> ["--identity-field", to_string(field)]
                  _ -> []
                end)

              igniter
              |> Igniter.compose_task(Mix.Tasks.AshAuthentication.Gen.Password, options)

            "magic_link", igniter ->
              options =
                options
                |> Keyword.take([:user, :identity_field])
                |> Enum.flat_map(fn
                  {:user, user} -> ["--user", inspect(user)]
                  {:identity_field, field} -> ["--identity-field", to_string(field)]
                  _ -> []
                end)

              igniter
              |> Igniter.compose_task(Mix.Tasks.AshAuthentication.Gen.MagicLink, options)

            "api_key", igniter ->
              options =
                options
                |> Keyword.take([:user, :identity_field])
                |> Enum.flat_map(fn
                  {:api_key, api_key} -> ["--api-key", api_key]
                  {:user, user} -> ["--user", inspect(user)]
                  {:identity_field, field} -> ["--identity-field", to_string(field)]
                  _ -> []
                end)

              igniter
              |> Igniter.compose_task(Mix.Tasks.AshAuthentication.Gen.ApiKey, options)
          end)

        {false, igniter} ->
          Igniter.add_issue(igniter, """
          User module #{inspect(options[:user])} was not found.

          Perhaps you have not yet installed ash_authentication?
          """)
      end
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
