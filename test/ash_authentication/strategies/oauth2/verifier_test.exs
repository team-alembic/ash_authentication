# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.VerifierTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Spark.Test

  defmodule Domain do
    @moduledoc false
    use Ash.Domain, validate_config_inclusion?: false

    resources do
      allow_unregistered? true
    end
  end

  test "an oauth2 strategy without an identity resource warns but still compiles" do
    {message, _location} =
      assert_dsl_warning {_, _} do
        defmodule NoIdentityUser do
          @moduledoc false
          use Ash.Resource,
            domain: AshAuthentication.Strategy.OAuth2.VerifierTest.Domain,
            extensions: [AshAuthentication],
            data_layer: Ash.DataLayer.Ets,
            validate_domain_inclusion?: false

          attributes do
            uuid_primary_key :id
            attribute :email, :ci_string, allow_nil?: false, public?: true
          end

          identities do
            identity :unique_email, [:email]
          end

          actions do
            defaults [:read]

            create :register_with_oauth2 do
              argument :user_info, :map, allow_nil?: false
              argument :oauth_tokens, :map, allow_nil?: false
              upsert? true
              upsert_identity :unique_email
              change AshAuthentication.GenerateTokenChange
            end
          end

          authentication do
            tokens do
              enabled? true
              token_resource __MODULE__.Token
              signing_secret fn _, _ -> {:ok, "test_secret_that_is_at_least_32_bytes_long"} end
            end

            strategies do
              oauth2 :oauth2 do
                client_id fn _, _ -> {:ok, "client_id"} end
                client_secret fn _, _ -> {:ok, "client_secret"} end
                redirect_uri fn _, _ -> {:ok, "https://example.com"} end
                base_url fn _, _ -> {:ok, "https://example.com"} end
                authorize_url fn _, _ -> {:ok, "https://example.com/authorize"} end
                token_url fn _, _ -> {:ok, "https://example.com/token"} end
                user_url fn _, _ -> {:ok, "https://example.com/userinfo"} end
              end
            end
          end
        end
      end

    assert message =~ "identity_resource"
    assert message =~ "mix ash_authentication.upgrade"
  end
end
