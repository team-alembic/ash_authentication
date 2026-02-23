# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.VerifierTest do
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

  describe "confirmation action name validation" do
    test "single confirmation add-on compiles successfully" do
      log_output =
        capture_io(:stderr, fn ->
          defmodule TestUser do
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
              defaults [:read, :create, :update, :destroy]

              update :confirm do
                accept [:email]
                argument :confirm, :string, allow_nil?: false
                change AshAuthentication.GenerateTokenChange
                change AshAuthentication.AddOn.Confirmation.ConfirmChange
                require_atomic? false
              end
            end

            authentication do
              session_identifier :jti

              tokens do
                enabled? true
                token_resource Example.Token
                signing_secret "test_secret_at_least_64_characters_long_for_proper_security"
              end

              add_ons do
                confirmation :confirm do
                  monitor_fields [:email]
                  require_interaction? true
                  sender fn _user, _token, _opts -> :ok end
                end
              end
            end

            identities do
              identity :unique_email, [:email], pre_check?: true
            end
          end
        end)

      assert log_output == ""
    end

    test "multiple confirmation add-ons with unique action names compile successfully" do
      log_output =
        capture_io(:stderr, fn ->
          defmodule TestUserMultiple do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true
              attribute :phone, :string, allow_nil?: true, public?: true
            end

            actions do
              defaults [:read, :create, :update, :destroy]

              update :confirm_email do
                accept [:email]
                argument :confirm, :string, allow_nil?: false
                change AshAuthentication.GenerateTokenChange
                change AshAuthentication.AddOn.Confirmation.ConfirmChange
                require_atomic? false
              end

              update :confirm_phone do
                accept [:phone]
                argument :confirm, :string, allow_nil?: false
                change AshAuthentication.GenerateTokenChange
                change AshAuthentication.AddOn.Confirmation.ConfirmChange
                require_atomic? false
              end
            end

            authentication do
              session_identifier :jti

              tokens do
                enabled? true
                token_resource Example.Token
                signing_secret "test_secret_at_least_64_characters_long_for_proper_security"
              end

              add_ons do
                confirmation :email_confirm do
                  confirm_action_name :confirm_email
                  monitor_fields [:email]
                  require_interaction? true
                  sender fn _user, _token, _opts -> :ok end
                end

                confirmation :phone_confirm do
                  confirm_action_name :confirm_phone
                  monitor_fields [:phone]
                  require_interaction? true
                  sender fn _user, _token, _opts -> :ok end
                end
              end
            end

            identities do
              identity :unique_email, [:email], pre_check?: true
            end
          end
        end)

      assert log_output == ""
    end

    test "conflicting confirmation action names raise clear error" do
      log_output =
        capture_io(:stderr, fn ->
          defmodule TestUserConflict do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true
              attribute :phone, :string, allow_nil?: true, public?: true
            end

            actions do
              defaults [:read, :create, :update, :destroy]

              update :confirm do
                accept [:email, :phone]
                argument :confirm, :string, allow_nil?: false
                change AshAuthentication.GenerateTokenChange
                change AshAuthentication.AddOn.Confirmation.ConfirmChange
                require_atomic? false
              end
            end

            authentication do
              tokens do
                enabled? true
                token_resource Example.Token

                signing_secret "test_secret_at_least_64_characters_long_for_proper_security"
              end

              add_ons do
                confirmation :email_confirm do
                  confirm_action_name :confirm
                  monitor_fields [:email]
                  require_interaction? true
                  sender fn _user, _token, _opts -> :ok end
                end

                confirmation :phone_confirm do
                  confirm_action_name :confirm
                  monitor_fields [:phone]
                  require_interaction? true
                  sender fn _user, _token, _opts -> :ok end
                end
              end
            end

            identities do
              identity :unique_email, [:email]
            end
          end
        end)

      assert log_output =~
               ~r/Multiple confirmation add-ons are configured with conflicting action names/
    end

    test "error message includes module name and helpful guidance" do
      log_output =
        capture_io(:stderr, fn ->
          defmodule TestUserConflictWithModule do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshAuthentication],
              domain: TestDomain

            attributes do
              uuid_primary_key :id
              attribute :email, :ci_string, allow_nil?: false, public?: true
              attribute :phone, :string, allow_nil?: true, public?: true
            end

            actions do
              defaults [:read, :create, :update, :destroy]

              update :confirm do
                accept [:email, :phone]
                argument :confirm, :string, allow_nil?: false
                change AshAuthentication.GenerateTokenChange
                change AshAuthentication.AddOn.Confirmation.ConfirmChange
                require_atomic? false
              end
            end

            authentication do
              tokens do
                enabled? true
                token_resource Example.Token
                signing_secret "test_secret_at_least_64_characters_long_for_proper_security"
              end

              add_ons do
                confirmation :email_confirm do
                  monitor_fields [:email]
                  require_interaction? true
                  sender fn _user, _token, _opts -> :ok end
                end

                confirmation :phone_confirm do
                  monitor_fields [:phone]
                  require_interaction? true
                  sender fn _user, _token, _opts -> :ok end
                end
              end
            end

            identities do
              identity :unique_email, [:email]
            end
          end
        end)

      # Check that the error message contains helpful information
      assert log_output =~
               "Multiple confirmation add-ons are configured with conflicting action names"
    end
  end

  describe "require_token_presence_for_authentication? without store_all_tokens?" do
    test "raises an error when require_token_presence_for_authentication? is true but store_all_tokens? is false" do
      log_output =
        capture_io(:stderr, fn ->
          defmodule TestUserTokenRequiredWithoutStore do
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
              defaults [:read]
            end

            authentication do
              tokens do
                enabled? true
                store_all_tokens? false
                require_token_presence_for_authentication? true
                token_resource Example.Token
                signing_secret "test_secret_at_least_64_characters_long_for_proper_security"
              end

              strategies do
                password do
                  identity_field :email
                end
              end
            end

            identities do
              identity :unique_email, [:email], pre_check?: true
            end
          end
        end)

      assert log_output =~
               "`require_token_presence_for_authentication?` is enabled but `store_all_tokens?` is not"
    end
  end
end
