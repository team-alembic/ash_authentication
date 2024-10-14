# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.AddStrategyTest do
  use ExUnit.Case

  import Igniter.Test

  setup do
    igniter =
      test_project()
      |> Igniter.Project.Deps.add_dep({:simple_sat, ">= 0.0.0"})
      |> Igniter.Project.Formatter.add_formatter_plugin(Spark.Formatter)
      |> Igniter.compose_task("ash_authentication.install", ["--yes"])
      |> apply_igniter!()

    [igniter: igniter]
  end

  describe "password" do
    test "adds the password strategy to the user", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      26 + |    strategies do
      27 + |      password :password do
      28 + |        identity_field(:email)
      29 + |
      30 + |        resettable do
      31 + |          sender(Test.Accounts.User.Senders.SendPasswordResetEmail)
      32 + |        end
      33 + |      end
      34 + |    end
      """)
    end

    test "adds the identity to the user resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      202 + |  identities do
      203 + |    identity(:unique_email, [:email])
      204 + |  end
      """)
    end

    test "adds the attributes to the user resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      45 + |    attribute :email, :ci_string do
      46 + |      allow_nil?(false)
      47 + |      public?(true)
      48 + |    end
      49 + |
      50 + |    attribute :hashed_password, :string do
      51 + |      allow_nil?(false)
      52 + |      sensitive?(true)
      53 + |    end
      """)
    end

    test "adds the password actions to the user resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      64 + |    read :sign_in_with_password do
      65 + |      description("Attempt to sign in using a email and password.")
      66 + |      get?(true)
      67 + |
      68 + |      argument :email, :ci_string do
      69 + |        description("The email to use for retrieving the user.")
      70 + |        allow_nil?(false)
      71 + |      end
      72 + |
      73 + |      argument :password, :string do
      74 + |        description("The password to check for the matching user.")
      75 + |        allow_nil?(false)
      76 + |        sensitive?(true)
      77 + |      end
      78 + |
      79 + |      # validates the provided email and password and generates a token
      80 + |      prepare(AshAuthentication.Strategy.Password.SignInPreparation)
      81 + |
      82 + |      metadata :token, :string do
      83 + |        description("A JWT that can be used to authenticate the user.")
      84 + |        allow_nil?(false)
      85 + |      end
      86 + |    end
      87 + |
      88 + |    read :sign_in_with_token do
      89 + |      # In the generated sign in components, we generate a validate the
      90 + |      # email and password directly in the LiveView
      91 + |      # and generate a short-lived token that can be used to sign in over
      92 + |      # a standard controller action, exchanging it for a standard token.
      93 + |      # This action performs that exchange. If you do not use the generated
      94 + |      # liveviews, you may remove this action, and set
      95 + |      # `sign_in_tokens_enabled? false` in the password strategy.
      96 + |
      97 + |      description("Attempt to sign in using a short-lived sign in token.")
      98 + |      get?(true)
      99 + |
      100 + |      argument :token, :string do
      101 + |        description("The short-lived sign in token.")
      102 + |        allow_nil?(false)
      103 + |        sensitive?(true)
      104 + |      end
      105 + |
      106 + |      # validates the provided sign in token and generates a token
      107 + |      prepare(AshAuthentication.Strategy.Password.SignInWithTokenPreparation)
      108 + |
      109 + |      metadata :token, :string do
      110 + |        description("A JWT that can be used to authenticate the user.")
      111 + |        allow_nil?(false)
      112 + |      end
      113 + |    end
      114 + |
      115 + |    create :register_with_password do
      116 + |      description("Register a new user with a email and password.")
      117 + |      accept([:email])
      118 + |
      119 + |      argument :password, :string do
      120 + |        description("The proposed password for the user, in plain text.")
      121 + |        allow_nil?(false)
      122 + |        constraints(min_length: 8)
      123 + |        sensitive?(true)
      124 + |      end
      125 + |
      126 + |      argument :password_confirmation, :string do
      127 + |        description("The proposed password for the user (again), in plain text.")
      128 + |        allow_nil?(false)
      129 + |        sensitive?(true)
      130 + |      end
      131 + |
      132 + |      # Hashes the provided password
      133 + |      change(AshAuthentication.Strategy.Password.HashPasswordChange)
      134 + |
      135 + |      # Generates an authentication token for the user
      136 + |      change(AshAuthentication.GenerateTokenChange)
      137 + |
      138 + |      # validates that the password matches the confirmation
      139 + |      validate(AshAuthentication.Strategy.Password.PasswordConfirmationValidation)
      140 + |
      141 + |      metadata :token, :string do
      142 + |        description("A JWT that can be used to authenticate the user.")
      143 + |        allow_nil?(false)
      144 + |      end
      145 + |    end
      146 + |
      147 + |    action :request_password_reset do
      148 + |      description("Send password reset instructions to a user if they exist.")
      149 + |
      150 + |      argument :email, :ci_string do
      151 + |        allow_nil?(false)
      152 + |      end
      153 + |
      154 + |      # creates a reset token and invokes the relevant senders
      155 + |      run({AshAuthentication.Strategy.Password.RequestPasswordReset, action: :get_by_email})
      156 + |    end
      157 + |
      158 + |    read :get_by_email do
      159 + |      description("Looks up a user by their email")
      160 + |      get?(true)
      161 + |
      162 + |      argument :email, :ci_string do
      163 + |        allow_nil?(false)
      164 + |      end
      165 + |
      166 + |      filter(expr(email == ^arg(:email)))
      167 + |    end
      168 + |
      169 + |    update :reset_password do
      170 + |      argument :reset_token, :string do
      171 + |        allow_nil?(false)
      172 + |        sensitive?(true)
      173 + |      end
      174 + |
      175 + |      argument :password, :string do
      176 + |        description("The proposed password for the user, in plain text.")
      177 + |        allow_nil?(false)
      178 + |        constraints(min_length: 8)
      179 + |        sensitive?(true)
      180 + |      end
      181 + |
      182 + |      argument :password_confirmation, :string do
      183 + |        description("The proposed password for the user (again), in plain text.")
      184 + |        allow_nil?(false)
      185 + |        sensitive?(true)
      186 + |      end
      187 + |
      188 + |      # validates the provided reset token
      189 + |      validate(AshAuthentication.Strategy.Password.ResetTokenValidation)
      190 + |
      191 + |      # validates that the password matches the confirmation
      192 + |      validate(AshAuthentication.Strategy.Password.PasswordConfirmationValidation)
      193 + |
      194 + |      # Hashes the provided password
      195 + |      change(AshAuthentication.Strategy.Password.HashPasswordChange)
      196 + |
      197 + |      # Generates an authentication token for the user
      198 + |      change(AshAuthentication.GenerateTokenChange)
      199 + |    end
      """)
    end

    test "adds the bcrypt dependency", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
      |> assert_has_patch("mix.exs", """
      25 + |      bcrypt_elixir: "~> 3.0",
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

          \#{url(~p"/password-reset/\#{token}")}
          \"\"\")
        end
      end
      """)
    end
  end
end
