# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.CustomFieldsTest do
  use ExUnit.Case, async: true

  alias Ash.Resource.Attribute
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.CustomFields
  alias AshAuthentication.Strategy.WebAuthn

  describe "register_fields/1" do
    test "returns attribute definitions and secret? flags for the webauthn strategy's register_action_accept" do
      strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)

      assert [{%Attribute{name: :name, writable?: true, public?: true}, false}] =
               CustomFields.register_fields(strategy)
    end

    test "excludes the identity field even when listed" do
      strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)
      strategy = %{strategy | register_action_accept: [:email, :name]}

      assert [{%Attribute{name: :name}, false}] = CustomFields.register_fields(strategy)
    end

    test "excludes names which don't resolve to public writable attributes" do
      strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)

      # `:created_at` exists but is a non-public, non-writable timestamp;
      # `:no_such_attribute` doesn't resolve at all. Both must be dropped.
      strategy = %{
        strategy
        | register_action_accept: [:created_at, :no_such_attribute, :name]
      }

      assert [{%Attribute{name: :name}, false}] = CustomFields.register_fields(strategy)
    end

    test "returns the declared secret? confirmation for sensitive fields" do
      strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)

      strategy = %{strategy | register_action_accept: [personal_number: [secret?: true]]}

      assert [{%Attribute{name: :personal_number}, true}] =
               CustomFields.register_fields(strategy)

      strategy = %{strategy | register_action_accept: [personal_number: [secret?: false]]}

      assert [{%Attribute{name: :personal_number}, false}] =
               CustomFields.register_fields(strategy)
    end

    test "asks for a secret? confirmation when a sensitive field lacks one" do
      strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)
      strategy = %{strategy | register_action_accept: [:personal_number]}

      error = assert_raise ArgumentError, fn -> CustomFields.register_fields(strategy) end

      assert error.message =~ "sensitive?: true"
      assert error.message =~ "personal_number: [secret?: false]"
    end

    test "returns an empty list for strategies without register_action_accept" do
      strategy = Info.strategy!(Example.User, :api_key)

      assert [] = CustomFields.register_fields(strategy)
    end
  end

  describe "accept_names/1" do
    test "strips confirmation options down to field names" do
      assert [:a, :b, :c] = CustomFields.accept_names([:a, {:b, [secret?: true]}, :c])
    end
  end

  describe "verify_secret_confirmations/2" do
    test "passes for non-sensitive fields and confirmed sensitive fields" do
      strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)

      assert :ok = CustomFields.verify_secret_confirmations(strategy, Example.UserWithWebAuthn)

      strategy = %{strategy | register_action_accept: [personal_number: [secret?: true]]}

      assert :ok = CustomFields.verify_secret_confirmations(strategy, Example.UserWithWebAuthn)
    end

    test "returns a DslError for unconfirmed sensitive fields" do
      strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)
      strategy = %{strategy | register_action_accept: [:name, :personal_number]}

      assert {:error, error} =
               CustomFields.verify_secret_confirmations(strategy, Example.UserWithWebAuthn)

      assert Exception.message(error) =~ "sensitive?: true"
      assert Exception.message(error) =~ "personal_number: [secret?: false]"
      assert error.path == [:authentication, :strategies, :webauthn, :register_action_accept]
    end

    test "is wired into the webauthn strategy verifier" do
      strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)
      strategy = %{strategy | register_action_accept: [:personal_number]}

      assert {:error, %Spark.Error.DslError{}} =
               WebAuthn.verify(
                 strategy,
                 Example.UserWithWebAuthn.spark_dsl_config()
               )
    end
  end
end
