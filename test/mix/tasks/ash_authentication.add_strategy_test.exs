# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.AddStrategyTest do
  use ExUnit.Case

  import Igniter.Test

  @moduletag :igniter

  setup do
    igniter =
      test_project()
      |> Igniter.Project.Deps.add_dep({:simple_sat, ">= 0.0.0"})
      |> Igniter.compose_task("ash_authentication.install", ["--yes"])
      # These can be removed when https://github.com/hrzndhrn/rewrite/issues/39 is addressed (in igniter too)
      |> Igniter.Project.Formatter.remove_imported_dep(:ash_authentication)
      |> Igniter.Project.Formatter.remove_formatter_plugin(Spark.Formatter)
      |> apply_igniter!()

    [igniter: igniter]
  end

  describe "password" do
    test "adds the password strategy to the user", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    strategies do
      + |      password :password do
      + |        identity_field(:email)
      + |        hash_provider(AshAuthentication.BcryptProvider)
      + |
      + |        resettable do
      + |          sender(Test.Accounts.User.Senders.SendPasswordResetEmail)
      + |          # these configurations will be the default in a future release
      + |          password_reset_action_name(:reset_password_with_token)
      + |          request_password_reset_action_name(:request_password_reset_token)
      + |        end
      + |      end
      + |    end
      """)
    end

    test "the `bcrypt` hash provider can be selected", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", [
        "password",
        "--hash-provider",
        "bcrypt"
      ])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    strategies do
      + |      password :password do
      + |        identity_field(:email)
      + |        hash_provider(AshAuthentication.BcryptProvider)
      + |
      + |        resettable do
      + |          sender(Test.Accounts.User.Senders.SendPasswordResetEmail)
      + |          # these configurations will be the default in a future release
      + |          password_reset_action_name(:reset_password_with_token)
      + |          request_password_reset_action_name(:request_password_reset_token)
      + |        end
      + |      end
      + |    end
      """)
    end

    test "the `argon2` hash provider can be selected", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", [
        "password",
        "--hash-provider",
        "argon2"
      ])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    strategies do
      + |      password :password do
      + |        identity_field(:email)
      + |        hash_provider(AshAuthentication.Argon2Provider)
      + |
      + |        resettable do
      + |          sender(Test.Accounts.User.Senders.SendPasswordResetEmail)
      + |          # these configurations will be the default in a future release
      + |          password_reset_action_name(:reset_password_with_token)
      + |          request_password_reset_action_name(:request_password_reset_token)
      + |        end
      + |      end
      + |    end
      """)
    end

    test "an arbitrary hash provider can be entered", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", [
        "password",
        "--hash-provider",
        "MyApp.ExampleHashProvider"
      ])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    strategies do
      + |      password :password do
      + |        identity_field(:email)
      + |        hash_provider(MyApp.ExampleHashProvider)
      + |
      + |        resettable do
      + |          sender(Test.Accounts.User.Senders.SendPasswordResetEmail)
      + |          # these configurations will be the default in a future release
      + |          password_reset_action_name(:reset_password_with_token)
      + |          request_password_reset_action_name(:request_password_reset_token)
      + |        end
      + |      end
      + |    end
      """)
    end

    test "adds the identity to the user resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |  identities do
      + |    identity(:unique_email, [:email])
      + |  end
      """)
    end

    test "adds the attributes to the user resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    attribute :email, :ci_string do
      + |      allow_nil?(false)
      + |      public?(true)
      + |    end
      + |
      + |    attribute :hashed_password, :string do
      + |      allow_nil?(false)
      + |      sensitive?(true)
      + |    end
      + |
      + |    attribute(:confirmed_at, :utc_datetime_usec)
      """)
    end

    test "adds the password actions to the user resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    read :sign_in_with_password do
      + |      description("Attempt to sign in using a email and password.")
      + |      get?(true)
      + |
      + |      argument :email, :ci_string do
      + |        description("The email to use for retrieving the user.")
      + |        allow_nil?(false)
      + |      end
      + |
      + |      argument :password, :string do
      + |        description("The password to check for the matching user.")
      + |        allow_nil?(false)
      + |        sensitive?(true)
      + |      end
      + |
      + |      # validates the provided email and password and generates a token
      + |      prepare(AshAuthentication.Strategy.Password.SignInPreparation)
      + |
      + |      metadata :token, :string do
      + |        description("A JWT that can be used to authenticate the user.")
      + |        allow_nil?(false)
      + |      end
      + |    end
      + |
      + |    read :sign_in_with_token do
      + |      # In the generated sign in components, we validate the
      + |      # email and password directly in the LiveView
      + |      # and generate a short-lived token that can be used to sign in over
      + |      # a standard controller action, exchanging it for a standard token.
      + |      # This action performs that exchange. If you do not use the generated
      + |      # liveviews, you may remove this action, and set
      + |      # `sign_in_tokens_enabled? false` in the password strategy.
      + |
      + |      description("Attempt to sign in using a short-lived sign in token.")
      + |      get?(true)
      + |
      + |      argument :token, :string do
      + |        description("The short-lived sign in token.")
      + |        allow_nil?(false)
      + |        sensitive?(true)
      + |      end
      + |
      + |      # validates the provided sign in token and generates a token
      + |      prepare(AshAuthentication.Strategy.Password.SignInWithTokenPreparation)
      + |
      + |      metadata :token, :string do
      + |        description("A JWT that can be used to authenticate the user.")
      + |        allow_nil?(false)
      + |      end
      + |    end
      + |
      + |    create :register_with_password do
      + |      description("Register a new user with a email and password.")
      + |
      + |      argument :email, :ci_string do
      + |        allow_nil?(false)
      + |      end
      + |
      + |      argument :password, :string do
      + |        description("The proposed password for the user, in plain text.")
      + |        allow_nil?(false)
      + |        constraints(min_length: 8)
      + |        sensitive?(true)
      + |      end
      + |
      + |      argument :password_confirmation, :string do
      + |        description("The proposed password for the user (again), in plain text.")
      + |        allow_nil?(false)
      + |        sensitive?(true)
      + |      end
      + |
      + |      # Sets the email from the argument
      + |      change(set_attribute(:email, arg(:email)))
      + |
      + |      # Hashes the provided password
      + |      change(AshAuthentication.Strategy.Password.HashPasswordChange)
      + |
      + |      # Generates an authentication token for the user
      + |      change(AshAuthentication.GenerateTokenChange)
      + |
      + |      # validates that the password matches the confirmation
      + |      validate(AshAuthentication.Strategy.Password.PasswordConfirmationValidation)
      + |
      + |      metadata :token, :string do
      + |        description("A JWT that can be used to authenticate the user.")
      + |        allow_nil?(false)
      + |      end
      + |    end
      + |
      + |    action :request_password_reset_token do
      + |      description("Send password reset instructions to a user if they exist.")
      + |
      + |      argument :email, :ci_string do
      + |        allow_nil?(false)
      + |      end
      + |
      + |      # creates a reset token and invokes the relevant senders
      + |      run({AshAuthentication.Strategy.Password.RequestPasswordReset, action: :get_by_email})
      + |    end
      + |
      + |    read :get_by_email do
      + |      description("Looks up a user by their email")
      + |
      + |      argument :email, :ci_string do
      + |        allow_nil?(false)
      + |      end
      + |
      + |      get_by :email
      + |    end
      + |
      + |    update :reset_password_with_token do
      + |      argument :reset_token, :string do
      + |        allow_nil?(false)
      + |        sensitive?(true)
      + |      end
      + |
      + |      argument :password, :string do
      + |        description("The proposed password for the user, in plain text.")
      + |        allow_nil?(false)
      + |        constraints(min_length: 8)
      + |        sensitive?(true)
      + |      end
      + |
      + |      argument :password_confirmation, :string do
      + |        description("The proposed password for the user (again), in plain text.")
      + |        allow_nil?(false)
      + |        sensitive?(true)
      + |      end
      + |
      + |      # validates the provided reset token
      + |      validate(AshAuthentication.Strategy.Password.ResetTokenValidation)
      + |
      + |      # validates that the password matches the confirmation
      + |      validate(AshAuthentication.Strategy.Password.PasswordConfirmationValidation)
      + |
      + |      # Hashes the provided password
      + |      change(AshAuthentication.Strategy.Password.HashPasswordChange)
      + |
      + |      # Generates an authentication token for the user
      + |      change(AshAuthentication.GenerateTokenChange)
      + |    end
      """)
    end

    test "adds the bcrypt_elixir dependency when no hash provider is selected", %{
      igniter: igniter
    } do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_has_patch("mix.exs", """
      + |      {:bcrypt_elixir, "~> 3.0"},
      """)
    end

    test "adds the bcrypt_elixir dependency when the bcrypt hash provider is selected", %{
      igniter: igniter
    } do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", [
        "password",
        "--hash-provider",
        "bcrypt"
      ])
      |> assert_has_patch("mix.exs", """
      + |      {:bcrypt_elixir, "~> 3.0"},
      """)
    end

    test "adds the argon2_elixir dependency when the argon2 hash provider is selected", %{
      igniter: igniter
    } do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", [
        "password",
        "--hash-provider",
        "argon2"
      ])
      |> assert_has_patch("mix.exs", """
      + |      {:argon2_elixir, "~> 4.0"},
      """)
    end

    test "creates a phoenix-idiomatic password reset sender", %{igniter: igniter} do
      igniter
      |> Igniter.Project.Module.create_module(TestWeb, "")
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_creates("lib/test/accounts/user/senders/send_password_reset_email.ex", """
      defmodule Test.Accounts.User.Senders.SendPasswordResetEmail do
        @moduledoc \"\"\"
        Sends a password reset email
        \"\"\"

        use AshAuthentication.Sender
        use TestWeb, :verified_routes

        @impl true
        def send(_user, token, _) do
          # Example of how you might send this email
          # Test.Accounts.Emails.send_password_reset_email(
          #   user,
          #   token
          # )

          IO.puts(\"\"\"
          Click this link to reset your password:

          \#{url(~p"/password-reset/\#{token}")}
          \"\"\")
        end
      end
      """)
    end

    test "creates a plain password reset sender if you are not using phoenix", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_creates("lib/test/accounts/user/senders/send_password_reset_email.ex", """
      defmodule Test.Accounts.User.Senders.SendPasswordResetEmail do
        @moduledoc \"\"\"
        Sends a password reset email
        \"\"\"

        use AshAuthentication.Sender

        @impl true
        def send(_user, token, _) do
          IO.puts(\"\"\"
          Click this link to reset your password:

          /password-reset/\#{token}
          \"\"\")
        end
      end
      """)
    end
  end

  describe "api_key" do
    test "adds the api_key strategy to the user", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["api_key"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + | api_key :api_key do
      + |   api_key_relationship(:valid_api_keys)
      + |   api_key_hash_attribute(:api_key_hash)
      + | end
      """)
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + | has_many :valid_api_keys, Test.Accounts.ApiKey do
      + |   filter(expr(valid))
      + | end
      """)
    end

    test "creates the api key resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["api_key"])
      |> assert_creates("lib/test/accounts/api_key.ex", """
      defmodule Test.Accounts.ApiKey do
        use Ash.Resource,
          otp_app: :test,
          domain: Test.Accounts,
          data_layer: AshPostgres.DataLayer,
          authorizers: [Ash.Policy.Authorizer]

        attributes do
          uuid_primary_key(:id)

          attribute :api_key_hash, :binary do
            allow_nil?(false)
            sensitive?(true)
          end

          attribute :expires_at, :utc_datetime_usec do
            allow_nil?(false)
          end
        end

        relationships do
          belongs_to(:user, Test.Accounts.User)
        end

        actions do
          defaults([:read, :destroy])

          create :create do
            primary?(true)
            accept([:user_id, :expires_at])

            change(
              {AshAuthentication.Strategy.ApiKey.GenerateApiKey, prefix: :test, hash: :api_key_hash}
            )
          end
        end

        postgres do
          table("api_keys")
          repo(Test.Repo)
        end

        identities do
          identity(:unique_api_key, [:api_key_hash])
        end

        calculations do
          calculate(:valid, :boolean, expr(expires_at > now()))
        end

        policies do
          bypass AshAuthentication.Checks.AshAuthenticationInteraction do
            authorize_if(always())
          end
        end
      end
      """)
    end
  end

  describe "magic_link" do
    test "makes hashed_password optional", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> apply_igniter!()
      |> Igniter.compose_task("ash_authentication.add_strategy", ["magic_link"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
        |    attribute :hashed_password, :string do
      - |      allow_nil?(false)
        |      sensitive?(true)
        |    end
      """)
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |   action :request_magic_link do
      + |     argument :email, :ci_string do
      + |       allow_nil?(false)
      + |     end
      + |
      + |     run(AshAuthentication.Strategy.MagicLink.Request)
      + |   end
      """)
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |     magic_link do
      + |       identity_field(:email)
      + |       registration_enabled?(true)
      + |       require_interaction?(true)
      + |
      + |       sender(Test.Accounts.User.Senders.SendMagicLinkEmail)
      + |     end
      """)
    end
  end
end
