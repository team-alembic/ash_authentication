defmodule AshAuthentication.VerifierTest do
  @moduledoc false
  use ExUnit.Case, async: true

  defmodule TestDomain do
    @moduledoc false
    use Ash.Domain

    resources do
      allow_unregistered? true
    end
  end

  describe "confirmation action name validation" do
    test "single confirmation add-on compiles successfully" do
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

      # If we get here without an exception, the resource compiled successfully
    end

    test "multiple confirmation add-ons with unique action names compile successfully" do
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
          end

          update :confirm_phone do
            accept [:phone]
            argument :confirm, :string, allow_nil?: false
            change AshAuthentication.GenerateTokenChange
            change AshAuthentication.AddOn.Confirmation.ConfirmChange
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

      # If we get here without an exception, the resource compiled successfully
    end

    test "conflicting confirmation action names raise clear error" do
      assert_raise Spark.Error.DslError,
                   ~r/Multiple confirmation add-ons are configured with conflicting action names/,
                   fn ->
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
                   end
    end

    test "error message includes module name and helpful guidance" do
      exception =
        assert_raise Spark.Error.DslError, fn ->
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
        end

      # Check that the error message contains helpful information
      assert exception.message =~
               "Multiple confirmation add-ons are configured with conflicting action names"

      assert exception.message =~ ":confirm"
      assert exception.message =~ "TestUserConflictWithModule"
      assert exception.message =~ "confirm_action_name"
    end
  end
end
