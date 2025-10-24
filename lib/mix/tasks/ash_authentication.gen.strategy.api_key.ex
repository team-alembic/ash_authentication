# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.Gen.Strategy.ApiKey do
    use Igniter.Mix.Task

    @example "mix ash_authentication.gen.strategy.api_key"
    @shortdoc "Adds the api key strategy to your user resource"

    @moduledoc """
    #{@shortdoc}

    ## Example
    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` - The user resource. Defaults to `YourApp.Accounts.User`
    * `--identity-field`, `-i` - The field on the user resource that will be used to identify the user. Defaults to `email`.
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        schema: [
          user: :string,
          identity_field: :string
        ],
        aliases: [
          u: :user,
          i: :identity_field
        ],
        defaults: [
          identity_field: "email"
        ]
      }
    end

    def igniter(igniter) do
      default_user = Igniter.Project.Module.module_name(igniter, "Accounts.User")

      options =
        igniter.args.options
        |> Keyword.update(:identity_field, :email, &String.to_atom/1)
        |> Keyword.update(:user, default_user, &Igniter.Project.Module.parse/1)

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          igniter
          |> generate(options)
          |> Ash.Igniter.codegen("add_api_key_auth")

        {false, igniter} ->
          Igniter.add_issue(igniter, """
          User module #{inspect(options[:user])} was not found.

          Perhaps you have not yet installed ash_authentication?
          """)
      end
    end

    defp generate(igniter, options) do
      otp_app = Igniter.Project.Application.app_name(igniter)

      api_key =
        if api_key = options[:api_key] do
          Igniter.Project.Module.parse(api_key)
        else
          options[:user]
          |> Module.split()
          |> :lists.droplast()
          |> Enum.concat([ApiKey])
          |> Module.concat()
        end

      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, api_key)

      if exists? do
        Igniter.add_issue(
          igniter,
          """
          Api key resource already exists: #{inspect(api_key)}.
          Please use the `--api-key` option to provide a different name.
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

        token_prefix = ":" <> String.replace(String.downcase(to_string(otp_app)), "_", "")

        igniter
        |> Ash.Resource.Igniter.add_new_relationship(
          options[:user],
          :valid_api_keys,
          """
          has_many :valid_api_keys, #{inspect(api_key)} do
            filter expr(valid)
          end
          """
        )
        |> Igniter.compose_task("ash.gen.resource", [
          inspect(api_key),
          "--uuid-primary-key",
          "id",
          "--default-actions",
          "read,destroy",
          "--attribute",
          "api_key_hash:binary:required:sensitive",
          "--attribute",
          "expires_at:utc_datetime_usec:required",
          "--relationship",
          "belongs_to:user:#{inspect(options[:user])}",
          "--extend",
          extensions
        ])
        |> Ash.Resource.Igniter.add_new_action(api_key, :create, """
        create :create do
          primary? true
          accept [:user_id, :expires_at]

          change {AshAuthentication.Strategy.ApiKey.GenerateApiKey, prefix: #{token_prefix}, hash: :api_key_hash}
        end
        """)
        |> Ash.Resource.Igniter.add_new_identity(api_key, :unique_api_key, """
        identity :unique_api_key, [:api_key_hash]
        """)
        |> Ash.Resource.Igniter.add_new_calculation(api_key, :valid, """
        calculate :valid, :boolean, expr(expires_at > now())
        """)
        |> Ash.Resource.Igniter.add_bypass(
          api_key,
          quote do
            AshAuthentication.Checks.AshAuthenticationInteraction
          end,
          quote do
            authorize_if always()
          end
        )
        |> setup_api_key_phoenix(options)
        |> Ash.Resource.Igniter.add_new_action(options[:user], :sign_in_with_api_key, """
        read :sign_in_with_api_key do
          argument :api_key, :string, allow_nil?: false
          prepare AshAuthentication.Strategy.ApiKey.SignInPreparation
        end
        """)
        |> AshAuthentication.Igniter.add_new_strategy(
          options[:user],
          :api_key,
          :api_key,
          """
          api_key :api_key do
            api_key_relationship :valid_api_keys
            api_key_hash_attribute :api_key_hash
          end
          """
        )
      end
    end

    defp setup_api_key_phoenix(igniter, options) do
      case Igniter.Libs.Phoenix.select_router(
             igniter,
             "Which router would you like to add api key authentication to?"
           ) do
        {igniter, nil} ->
          igniter

        {igniter, router} ->
          igniter
          |> Igniter.Libs.Phoenix.append_to_pipeline(
            :api,
            """
            plug AshAuthentication.Strategy.ApiKey.Plug,
              resource: #{inspect(options[:user])},
              # if you want to require an api key to be supplied, set `required?` to true
              required?: false
            """,
            router: router
          )
      end
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.Gen.Strategy.ApiKey do
    @shortdoc "Adds the api key strategy to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.gen.strategy.api_key' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
