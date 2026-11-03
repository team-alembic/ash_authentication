# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.BruteForceValidationTest do
  @moduledoc """
  A strategy with a `brute_force_strategy` only protects actions that carry its
  preparation. The strategies add it to the actions they build; these tests
  cover actions defined on the resource, by hand or by a generator, without it.
  """
  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  alias Spark.Error.DslError

  defmodule TestDomain do
    @moduledoc false
    use Ash.Domain, validate_config_inclusion?: false

    resources do
      allow_unregistered? true
    end
  end

  defmodule TestAuditLog do
    @moduledoc false
    use Ash.Resource,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAuthentication.AuditLogResource],
      domain: TestDomain

    audit_log do
      write_batching do
        enabled? false
      end
    end
  end

  describe "password" do
    test "a hand-written sign-in action without the preparation is refused" do
      assert_raise DslError, ~r/sign_in_with_password.*would not be limited/s, fn ->
        defmodule PasswordSignInWithoutCheck do
          @moduledoc false
          use Ash.Resource,
            data_layer: Ash.DataLayer.Ets,
            extensions: [AshAuthentication],
            domain: TestDomain

          attributes do
            uuid_primary_key :id
            attribute :email, :ci_string, allow_nil?: false, public?: true
            attribute :hashed_password, :string, allow_nil?: true, sensitive?: true
          end

          actions do
            defaults [:read, :create]

            read :sign_in_with_password do
              get? true
              argument :email, :ci_string, allow_nil?: false
              argument :password, :string, allow_nil?: false, sensitive?: true
              prepare AshAuthentication.Strategy.Password.SignInPreparation
            end
          end

          authentication do
            add_ons do
              audit_log do
                audit_log_resource TestAuditLog
              end
            end

            strategies do
              password do
                identity_field :email
                sign_in_tokens_enabled? false
                brute_force_strategy {:audit_log, :audit_log}
              end
            end
          end

          identities do
            identity :unique_email, [:email], pre_check_with: TestDomain
          end
        end
      end
    end

    test "a hand-written sign-in action with the preparation is accepted" do
      defmodule PasswordSignInWithCheck do
        @moduledoc false
        use Ash.Resource,
          data_layer: Ash.DataLayer.Ets,
          extensions: [AshAuthentication],
          domain: TestDomain

        attributes do
          uuid_primary_key :id
          attribute :email, :ci_string, allow_nil?: false, public?: true
          attribute :hashed_password, :string, allow_nil?: true, sensitive?: true
        end

        actions do
          defaults [:read, :create]

          read :sign_in_with_password do
            get? true
            argument :email, :ci_string, allow_nil?: false
            argument :password, :string, allow_nil?: false, sensitive?: true

            prepare {AshAuthentication.AddOn.AuditLog.IdentityBruteForcePreparation,
                     action_name: :sign_in_with_password}

            prepare AshAuthentication.Strategy.Password.SignInPreparation
          end
        end

        authentication do
          add_ons do
            audit_log do
              audit_log_resource TestAuditLog
            end
          end

          strategies do
            password do
              identity_field :email
              sign_in_tokens_enabled? false
              brute_force_strategy {:audit_log, :audit_log}
            end
          end
        end

        identities do
          identity :unique_email, [:email], pre_check_with: TestDomain
        end
      end

      assert AshAuthentication.Info.strategy!(PasswordSignInWithCheck, :password)
    end

    test "a hand-written reset request action without the preparation is refused" do
      assert_raise DslError, ~r/request_password_reset_token.*would not be limited/s, fn ->
        defmodule PasswordResetRequestWithoutCheck do
          @moduledoc false
          use Ash.Resource,
            data_layer: Ash.DataLayer.Ets,
            extensions: [AshAuthentication],
            domain: TestDomain

          attributes do
            uuid_primary_key :id
            attribute :email, :ci_string, allow_nil?: false, public?: true
            attribute :hashed_password, :string, allow_nil?: true, sensitive?: true
          end

          actions do
            defaults [:read, :create]

            action :request_password_reset_token do
              argument :email, :ci_string, allow_nil?: false

              run {AshAuthentication.Strategy.Password.RequestPasswordReset,
                   action: :get_by_email}
            end
          end

          authentication do
            tokens do
              enabled? true
              token_resource Example.Token
              signing_secret "test_secret_at_least_64_characters_long_for_proper_security"
            end

            add_ons do
              audit_log do
                audit_log_resource TestAuditLog
              end
            end

            strategies do
              password do
                identity_field :email
                brute_force_strategy {:audit_log, :audit_log}

                resettable do
                  sender fn _user, _token, _opts -> :ok end
                  request_password_reset_action_name :request_password_reset_token
                end
              end
            end
          end

          identities do
            identity :unique_email, [:email], pre_check_with: TestDomain
          end
        end
      end
    end
  end

  describe "magic link" do
    test "a hand-written request action without the preparation is reported" do
      output =
        capture_io(:stderr, fn ->
          defmodule MagicLinkRequestWithoutCheck do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true
            end

            actions do
              defaults [:read, :create]

              action :request_magic_link do
                argument :email, :ci_string, allow_nil?: false
                run AshAuthentication.Strategy.MagicLink.Request
              end
            end

            authentication do
              tokens do
                enabled? true
                token_resource Example.Token
                signing_secret "test_secret_at_least_64_characters_long_for_proper_security"
              end

              add_ons do
                audit_log do
                  audit_log_resource TestAuditLog
                end
              end

              strategies do
                magic_link do
                  identity_field :email
                  sender fn _user, _token, _opts -> :ok end
                  brute_force_strategy {:audit_log, :audit_log}
                end
              end
            end

            identities do
              identity :unique_email, [:email], pre_check_with: TestDomain
            end
          end
        end)

      assert output =~ ~r/request_magic_link.*would not be limited/s
      assert output =~ "IdentityBruteForcePreparation"
    end
  end

  describe "one-time passwords" do
    test "a hand-written sign-in action without the preparation is reported" do
      output =
        capture_io(:stderr, fn ->
          defmodule OtpSignInWithoutCheck do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true
            end

            actions do
              defaults [:read, :create]

              read :sign_in_with_otp do
                get? true
                argument :email, :ci_string, allow_nil?: false
                argument :otp, :string, allow_nil?: false, sensitive?: true
                prepare AshAuthentication.Strategy.Otp.SignInPreparation
              end
            end

            authentication do
              tokens do
                enabled? true
                token_resource Example.Token
                signing_secret "test_secret_at_least_64_characters_long_for_proper_security"
              end

              add_ons do
                audit_log do
                  audit_log_resource TestAuditLog
                end
              end

              strategies do
                otp do
                  identity_field :email
                  sender fn _user, _otp, _opts -> :ok end
                  brute_force_strategy {:audit_log, :audit_log}
                end
              end
            end

            identities do
              identity :unique_email, [:email], pre_check_with: TestDomain
            end
          end
        end)

      assert output =~ ~r/sign_in_with_otp.*would not be limited/s
      assert output =~ "BruteForcePreparation"
    end

    test "a preparation strategy with registration enabled is reported" do
      output =
        capture_io(:stderr, fn ->
          defmodule OtpRegistrationWithPreparation do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true
            end

            actions do
              defaults [:read, :create]
            end

            authentication do
              session_identifier :jti

              tokens do
                enabled? true
                token_resource Example.Token
                signing_secret "test_secret_at_least_64_characters_long_for_proper_security"
              end

              strategies do
                otp do
                  identity_field :email
                  registration_enabled? true
                  sender fn _user, _otp, _opts -> :ok end
                  brute_force_strategy {:preparation, Example.TotpNoopPreparation}
                end
              end
            end

            identities do
              identity :unique_email, [:email], pre_check_with: TestDomain
            end
          end
        end)

      assert output =~ ~r/registration_enabled\?.*sign-in attempts would not be limited/s
      assert output =~ "Use `:rate_limit`"
    end
  end
end
