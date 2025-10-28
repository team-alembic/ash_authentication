# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.VerifierTest do
  @moduledoc false
  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

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

    attributes do
      uuid_v7_primary_key :id, writable?: true
      attribute :strategy, :atom, allow_nil?: false, public?: true
      attribute :action_name, :atom, allow_nil?: false, public?: true
      attribute :subject, :string, allow_nil?: true, public?: true
      attribute :resource, :atom, allow_nil?: false, public?: true
      attribute :status, :atom, allow_nil?: false, public?: true

      attribute :logged_at, :utc_datetime_usec,
        allow_nil?: false,
        public?: true,
        default: &DateTime.utc_now/0

      attribute :extra_data, :map, allow_nil?: false, public?: true, default: %{}
      create_timestamp :inserted_at
    end

    actions do
      defaults [:read]

      create :record_authentication_event do
        upsert? false
        accept [:strategy, :action_name, :subject, :resource, :status, :logged_at, :extra_data]
      end
    end
  end

  describe "verify_sensitive_fields/1" do
    setup do
      original = Application.get_env(:ash_authentication, :suppress_sensitive_field_warnings?)
      Application.put_env(:ash_authentication, :suppress_sensitive_field_warnings?, false)

      on_exit(fn ->
        Application.put_env(:ash_authentication, :suppress_sensitive_field_warnings?, original)
      end)
    end

    test "shows warning when sensitive attributes are included in audit log" do
      log_output =
        capture_io(:stderr, fn ->
          defmodule UserWithSensitiveFields do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true, sensitive?: true

              attribute :hashed_password, :string,
                allow_nil?: true,
                sensitive?: true,
                public?: false
            end

            actions do
              defaults [:read, :create, :update, :destroy]
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
                  include_fields [:email]
                end
              end

              strategies do
                password do
                  identity_field :email
                end
              end
            end

            identities do
              identity :unique_email, [:email]
            end
          end
        end)

      assert log_output =~ "AuditLog is configured to log sensitive fields: [:email]"
      assert log_output =~ "Sensitive fields are being explicitly included in audit logs"
      assert log_output =~ "config :ash_authentication, suppress_sensitive_field_warnings?: true"
    end

    test "shows warning for multiple sensitive fields" do
      log_output =
        capture_io(:stderr, fn ->
          defmodule UserWithMultipleSensitiveFields do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true, sensitive?: true
              attribute :phone_number, :string, allow_nil?: true, public?: true, sensitive?: true

              attribute :hashed_password, :string,
                allow_nil?: true,
                sensitive?: true,
                public?: false
            end

            actions do
              defaults [:read, :create, :update, :destroy]
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
                  include_fields [:email, :phone_number, :hashed_password]
                end
              end

              strategies do
                password do
                  identity_field :email
                end
              end
            end

            identities do
              identity :unique_email, [:email]
            end
          end
        end)

      assert log_output =~ ":email, :phone_number, :hashed_password"
    end

    test "no warning when including only non-sensitive fields" do
      log_output =
        capture_io(:stderr, fn ->
          defmodule UserWithNonSensitiveFields do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true, sensitive?: false
              attribute :name, :string, allow_nil?: true, public?: true

              attribute :hashed_password, :string,
                allow_nil?: true,
                sensitive?: true,
                public?: false
            end

            actions do
              defaults [:read, :create, :update, :destroy]
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
                  include_fields [:email, :name]
                end
              end

              strategies do
                password do
                  identity_field :email
                end
              end
            end

            identities do
              identity :unique_email, [:email]
            end
          end
        end)

      refute log_output =~ "AuditLog is configured to log sensitive fields"
    end

    test "no warning when include_fields is empty" do
      log_output =
        capture_io(:stderr, fn ->
          defmodule UserWithNoIncludeFields do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true, sensitive?: true

              attribute :hashed_password, :string,
                allow_nil?: true,
                sensitive?: true,
                public?: false
            end

            actions do
              defaults [:read, :create, :update, :destroy]
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
                end
              end
            end

            identities do
              identity :unique_email, [:email]
            end
          end
        end)

      refute log_output =~ "AuditLog is configured to log sensitive fields"
    end

    test "warning is suppressed when configuration flag is set" do
      # Save current config
      original_config =
        Application.get_env(:ash_authentication, :suppress_sensitive_field_warnings?)

      try do
        # Set the suppression flag
        Application.put_env(:ash_authentication, :suppress_sensitive_field_warnings?, true)

        log_output =
          capture_io(:stderr, fn ->
            defmodule UserWithSuppressedWarning do
              @moduledoc false
              use Ash.Resource,
                data_layer: Ash.DataLayer.Ets,
                extensions: [AshAuthentication],
                domain: TestDomain

              attributes do
                uuid_primary_key :id
                attribute :email, :ci_string, allow_nil?: false, public?: true, sensitive?: true

                attribute :hashed_password, :string,
                  allow_nil?: true,
                  sensitive?: true,
                  public?: false
              end

              actions do
                defaults [:read, :create, :update, :destroy]
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
                    include_fields [:email, :hashed_password]
                  end
                end

                strategies do
                  password do
                    identity_field :email
                  end
                end
              end

              identities do
                identity :unique_email, [:email]
              end
            end
          end)

        # No warning should be shown when suppressed
        refute log_output =~ "AuditLog is configured to log sensitive fields"
      after
        # Restore original config
        if original_config do
          Application.put_env(
            :ash_authentication,
            :suppress_sensitive_field_warnings?,
            original_config
          )
        else
          Application.delete_env(:ash_authentication, :suppress_sensitive_field_warnings?)
        end
      end
    end

    test "warning includes sensitive action arguments" do
      log_output =
        capture_io(:stderr, fn ->
          defmodule UserWithSensitiveArguments do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true

              attribute :hashed_password, :string,
                allow_nil?: true,
                sensitive?: true,
                public?: false
            end

            actions do
              defaults [:read, :destroy]

              create :register_with_password do
                accept [:email]
                argument :email, :ci_string, allow_nil?: false
                argument :password, :string, allow_nil?: false, sensitive?: true
                argument :password_confirmation, :string, allow_nil?: false, sensitive?: true

                validate AshAuthentication.Strategy.Password.PasswordConfirmationValidation

                change AshAuthentication.GenerateTokenChange
                change AshAuthentication.Strategy.Password.HashPasswordChange
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
                  include_fields [:password, :password_confirmation]
                end
              end

              strategies do
                password do
                  identity_field :email
                end
              end
            end

            identities do
              identity :unique_email, [:email]
            end
          end
        end)

      assert log_output =~ ":password, :password_confirmation"
    end

    test "handles fields that don't exist gracefully" do
      log_output =
        capture_io(:stderr, fn ->
          defmodule UserWithNonExistentFields do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true

              attribute :hashed_password, :string,
                allow_nil?: true,
                sensitive?: true,
                public?: false
            end

            actions do
              defaults [:read, :create, :update, :destroy]
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
                  include_fields [:non_existent_field]
                end
              end

              strategies do
                password do
                  identity_field :email
                end
              end
            end

            identities do
              identity :unique_email, [:email]
            end
          end
        end)

      # Should not crash, and should not show warning for non-existent fields
      refute log_output =~ "AuditLog is configured to log sensitive fields"
    end
  end
end
