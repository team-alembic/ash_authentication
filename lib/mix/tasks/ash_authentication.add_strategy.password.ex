# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Password do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy.password"

    @shortdoc "Adds password authentication to your user resource"

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
    * `--hash-provider` - The hash provider to use, either `bcrypt` or `argon2`. Defaults to `bcrypt`.
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [],
        composes: [
          "ash_authentication.add_add_on.confirmation"
        ],
        schema: [
          accounts: :string,
          user: :string,
          identity_field: :string,
          hash_provider: :string
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
          |> password(options)
          |> AshAuthentication.Igniter.add_remember_me_strategy(options[:user])
          |> Ash.Igniter.codegen("add_password_auth")

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

    defp password(igniter, options) do
      hash_provider =
        cond do
          options[:hash_provider] |> to_string() |> String.downcase() == "bcrypt" ->
            "AshAuthentication.BcryptProvider"

          options[:hash_provider] |> to_string() |> String.downcase() == "argon2" ->
            "AshAuthentication.Argon2Provider"

          is_binary(options[:hash_provider]) ->
            options[:hash_provider]

          true ->
            "AshAuthentication.BcryptProvider"
        end

      igniter =
        if hash_provider == "AshAuthentication.BcryptProvider" do
          Igniter.Project.Deps.add_dep(igniter, {:bcrypt_elixir, "~> 3.0"})
        else
          igniter
        end

      igniter =
        if hash_provider == "AshAuthentication.Argon2Provider" do
          Igniter.Project.Deps.add_dep(igniter, {:argon2_elixir, "~> 4.0"})
        else
          igniter
        end

      sender = Module.concat(options[:user], Senders.SendPasswordResetEmail)

      {igniter, _, zipper} =
        igniter
        |> Igniter.Project.Module.find_module!(options[:user])

      allow_nil_line =
        zipper
        |> Igniter.Code.Function.move_to_function_call(:magic_link, [1, 2])
        |> case do
          {:ok, _} -> ""
          _ -> "allow_nil? false"
        end

      igniter
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], options[:identity_field], """
      attribute #{inspect(options[:identity_field])}, :ci_string do
        allow_nil? false
        public? true
      end
      """)
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], :hashed_password, """
      attribute :hashed_password, :string do
        #{allow_nil_line}
        sensitive? true
      end
      """)
      |> AshAuthentication.Igniter.ensure_identity(options[:user], options[:identity_field])
      |> AshAuthentication.Igniter.add_new_strategy(options[:user], :password, :password, """
      password :password do
        identity_field #{inspect(options[:identity_field])}
        hash_provider #{hash_provider}

        resettable do
          sender #{inspect(sender)}
          # these configurations will be the default in a future release
          password_reset_action_name :reset_password_with_token
          request_password_reset_action_name :request_password_reset_token
        end
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :change_password, """
      update :change_password do
        # Use this action to allow users to change their password by providing
        # their current password and a new password.

        require_atomic? false
        accept []
        argument :current_password, :string, sensitive?: true, allow_nil?: false
        argument :password, :string, sensitive?: true, allow_nil?: false, constraints: [min_length: 8]
        argument :password_confirmation, :string, sensitive?: true, allow_nil?: false

        validate confirm(:password, :password_confirmation)
        validate {AshAuthentication.Strategy.Password.PasswordValidation, strategy_name: :password, password_argument: :current_password}

        change {AshAuthentication.Strategy.Password.HashPasswordChange, strategy_name: :password}
      end
      """)
      |> generate_sign_in_and_registration(options)
      |> generate_reset(sender, options)
      |> add_confirmation(options)
      |> Ash.Igniter.codegen("add_password_authentication")
    end

    defp add_confirmation(igniter, options) do
      if options[:identity_field] == :email do
        Igniter.compose_task(
          igniter,
          "ash_authentication.add_add_on.confirmation",
          [
            "--user",
            inspect(options[:user]),
            "--identity-field",
            to_string(options[:identity_field])
          ]
        )
      else
        igniter
      end
    end

    defp generate_reset(igniter, sender, options) do
      igniter
      |> create_reset_sender(sender, options)
      |> Ash.Resource.Igniter.add_new_action(
        options[:user],
        :request_password_reset_token,
        """
        action :request_password_reset_token do
          description "Send password reset instructions to a user if they exist."

          argument #{inspect(options[:identity_field])}, :ci_string do
            allow_nil? false
          end

          # creates a reset token and invokes the relevant senders
          run {AshAuthentication.Strategy.Password.RequestPasswordReset, action: #{inspect(:"get_by_#{options[:identity_field]}")}}
        end
        """
      )
      |> AshAuthentication.Igniter.ensure_get_by_action(options[:user], options[:identity_field])
      |> Ash.Resource.Igniter.add_new_action(options[:user], :reset_password_with_token, """
      update :reset_password_with_token do
        argument :reset_token, :string do
          allow_nil? false
          sensitive? true
        end

        argument :password, :string do
          description "The proposed password for the user, in plain text."
          allow_nil? false
          constraints [min_length: 8]
          sensitive? true
        end

        argument :password_confirmation, :string do
          description "The proposed password for the user (again), in plain text."
          allow_nil? false
          sensitive? true
        end

        # validates the provided reset token
        validate AshAuthentication.Strategy.Password.ResetTokenValidation

        # validates that the password matches the confirmation
        validate AshAuthentication.Strategy.Password.PasswordConfirmationValidation

        # Hashes the provided password
        change AshAuthentication.Strategy.Password.HashPasswordChange

        # Generates an authentication token for the user
        change AshAuthentication.GenerateTokenChange
      end
      """)
    end

    defp create_reset_sender(igniter, sender, _options) do
      Igniter.Project.Module.create_module(
        igniter,
        sender,
        ~s'''
        @moduledoc """
        Sends a password reset email
        """

        use AshAuthentication.Sender

        @impl true
        def send(_user, token, _) do
          IO.puts("""
          Click this link to reset your password:

          /password-reset/\#{token}
          """)
        end
        ''',
        on_exists: :warning
      )
    end

    defp generate_sign_in_and_registration(igniter, options) do
      igniter
      |> Ash.Resource.Igniter.add_new_action(options[:user], :sign_in_with_password, """
      read :sign_in_with_password do
        description "Attempt to sign in using a #{options[:identity_field]} and password."
        get? true

        argument #{inspect(options[:identity_field])}, :ci_string do
          description "The #{options[:identity_field]} to use for retrieving the user."
          allow_nil? false
        end

        argument :password, :string do
          description "The password to check for the matching user."
          allow_nil? false
          sensitive? true
        end

        argument :remember_me, :boolean do
          description "Whether to generate a remember me token"
          allow_nil? true
        end

        # validates the provided #{options[:identity_field]} and password and generates a token
        prepare AshAuthentication.Strategy.Password.SignInPreparation

        # generates a remember me token if the remember_me argument is true
        prepare {AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation,
                strategy_name: :remember_me}

        metadata :token, :string do
          description "A JWT that can be used to authenticate the user."
          allow_nil? false
        end
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :sign_in_with_token, """
      read :sign_in_with_token do
        # In the generated sign in components, we validate the
        # #{options[:identity_field]} and password directly in the LiveView
        # and generate a short-lived token that can be used to sign in over
        # a standard controller action, exchanging it for a standard token.
        # This action performs that exchange. If you do not use the generated
        # liveviews, you may remove this action, and set
        # `sign_in_tokens_enabled? false` in the password strategy.

        description "Attempt to sign in using a short-lived sign in token."
        get? true

        argument :token, :string do
          description "The short-lived sign in token."
          allow_nil? false
          sensitive? true
        end

        # validates the provided sign in token and generates a token
        prepare AshAuthentication.Strategy.Password.SignInWithTokenPreparation

        metadata :token, :string do
          description "A JWT that can be used to authenticate the user."
          allow_nil? false
        end
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :register_with_password, """
      create :register_with_password do
        description "Register a new user with a #{options[:identity_field]} and password."
        argument #{inspect(options[:identity_field])}, :ci_string do
          allow_nil? false
        end

        argument :password, :string do
          description "The proposed password for the user, in plain text."
          allow_nil? false
          constraints [min_length: 8]
          sensitive? true
        end

        argument :password_confirmation, :string do
          description "The proposed password for the user (again), in plain text."
          allow_nil? false
          sensitive? true
        end

        # Sets the #{options[:identity_field]} from the argument
        change set_attribute(#{inspect(options[:identity_field])}, arg(#{inspect(options[:identity_field])}))

        # Hashes the provided password
        change AshAuthentication.Strategy.Password.HashPasswordChange

        # Generates an authentication token for the user
        change AshAuthentication.GenerateTokenChange

        # validates that the password matches the confirmation
        validate AshAuthentication.Strategy.Password.PasswordConfirmationValidation

        metadata :token, :string do
          description "A JWT that can be used to authenticate the user."
          allow_nil? false
        end
      end
      """)
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Password do
    @shortdoc "Adds password authentication to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_strategy.password' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
