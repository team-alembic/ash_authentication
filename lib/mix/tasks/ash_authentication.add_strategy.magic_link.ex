# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.MagicLink do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy.magic_link"

    @shortdoc "Adds magic link authentication to your user resource"

    @moduledoc """
    #{@shortdoc}

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` -  The user resource. Defaults to `YourApp.Accounts.User`
    * `--identity-field`, `-i` - The field on the user resource that will be used to identify
      the user. Defaults to `email`
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

      if options[:identity_field] != :email do
        Mix.shell().error("""
        Could not add magic link strategy with identity field #{inspect(options[:identity_field])}.

        Please run `mix ash_authentication.add_strategy magic_link` without specifying a default
        """)

        exit({:shutdown, 1})
      end

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          igniter
          |> magic_link(options)
          |> AshAuthentication.Igniter.add_remember_me_strategy(options[:user])
          |> Ash.Igniter.codegen("add_magic_link_auth")

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
      |> Keyword.update!(:accounts, &AshAuthentication.Igniter.maybe_parse_module/1)
      |> Keyword.update!(:user, &AshAuthentication.Igniter.maybe_parse_module/1)
    end

    defp magic_link(igniter, options) do
      sender = Module.concat(options[:user], Senders.SendMagicLinkEmail)

      igniter
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], options[:identity_field], """
      attribute :#{options[:identity_field]}, :ci_string do
        allow_nil? false
        public? true
      end
      """)
      |> make_hashed_password_optional(options)
      |> AshAuthentication.Igniter.ensure_identity(options[:user], options[:identity_field])
      |> AshAuthentication.Igniter.ensure_get_by_action(options[:user], options[:identity_field])
      |> Ash.Resource.Igniter.add_new_action(options[:user], :sign_in_with_magic_link, """
      create :sign_in_with_magic_link do
        description "Sign in or register a user with magic link."

        argument :token, :string do
          description "The token from the magic link that was sent to the user"
          allow_nil? false
        end

        argument :remember_me, :boolean do
          description "Whether to generate a remember me token"
          allow_nil? true
        end

        upsert? true
        upsert_identity :unique_#{options[:identity_field]}
        upsert_fields [:#{options[:identity_field]}]

        # Uses the information from the token to create or sign in the user
        change AshAuthentication.Strategy.MagicLink.SignInChange

        change {AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenChange,
                strategy_name: :remember_me}

        metadata :token, :string do
          allow_nil? false
        end
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :request_magic_link, """
      action :request_magic_link do
        argument :#{options[:identity_field]}, :ci_string do
          allow_nil? false
        end

        run AshAuthentication.Strategy.MagicLink.Request
      end
      """)
      |> AshAuthentication.Igniter.add_new_strategy(options[:user], :magic_link, :magic_link, """
      magic_link do
        identity_field :#{options[:identity_field]}
        registration_enabled? true
        require_interaction? true

        sender #{inspect(sender)}
      end
      """)
      |> create_new_magic_link_sender(sender, options)
      |> add_magic_link_config()
    end

    defp add_magic_link_config(igniter) do
      otp_app = Igniter.Project.Application.app_name(igniter)

      igniter
      |> Igniter.Project.Config.configure_new(
        "config.exs",
        otp_app,
        [:ash_authentication, :return_error_on_invalid_magic_link_token?],
        true
      )
    end

    defp make_hashed_password_optional(igniter, options) do
      Igniter.Project.Module.find_and_update_module!(igniter, options[:user], fn zipper ->
        with {:ok, zipper} <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(
                 zipper,
                 :attributes,
                 1
               ),
             {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper),
             {:ok, zipper} <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(
                 zipper,
                 :attribute,
                 [1, 2, 3],
                 &Igniter.Code.Function.argument_equals?(&1, 0, :hashed_password)
               ),
             {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper),
             {:ok, zipper} <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(
                 zipper,
                 :allow_nil?,
                 1,
                 &Igniter.Code.Function.argument_equals?(&1, 0, false)
               ) do
          {:ok, Sourceror.Zipper.remove(zipper)}
        else
          _ ->
            {:ok, zipper}
        end
      end)
    end

    defp create_new_magic_link_sender(igniter, sender, _options) do
      Igniter.Project.Module.create_module(
        igniter,
        sender,
        ~s'''
        @moduledoc """
        Sends a magic link email
        """

        use AshAuthentication.Sender

        @impl true
        def send(user_or_email, token, _) do
          # if you get a user, its for a user that already exists.
          # if you get an email, then the user does not yet exist.

          email =
            case user_or_email do
              %{email: email} -> email
              email -> email
            end

          IO.puts("""
          Hello, \#{email}! Click this link to sign in:

          /auth/user/magic_link/?token=\#{token}
          """)
        end
        '''
      )
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.MagicLink do
    @shortdoc "Adds magic link authentication to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_strategy.magic_link' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
