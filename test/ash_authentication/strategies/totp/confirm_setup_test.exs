# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.ConfirmSetupTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Strategy}

  describe "TOTP confirm setup flow" do
    test "setup returns setup_token and totp_url (secret not on user)" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # User starts without a TOTP secret
      assert is_nil(user.totp_secret)

      # Setup TOTP - should return setup_token and totp_url, not store secret
      {:ok, user_with_pending_setup} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Secret should NOT be stored on user yet
      assert is_nil(user_with_pending_setup.totp_secret)

      # Metadata should contain setup_token and totp_url
      assert user_with_pending_setup.__metadata__.setup_token
      assert user_with_pending_setup.__metadata__.totp_url

      # TOTP URL should be properly formatted
      assert String.starts_with?(user_with_pending_setup.__metadata__.totp_url, "otpauth://totp/")
    end

    test "confirm_setup with valid code stores secret on user" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # Setup TOTP
      {:ok, user_with_pending_setup} = Strategy.action(strategy, :setup, %{user: user}, [])
      setup_token = user_with_pending_setup.__metadata__.setup_token
      totp_url = user_with_pending_setup.__metadata__.totp_url

      # Extract secret from TOTP URL for code generation
      %URI{query: query} = URI.parse(totp_url)
      %{"secret" => encoded_secret} = URI.decode_query(query)
      secret = Base.decode32!(encoded_secret, padding: false)

      # Generate a valid code
      code = NimbleTOTP.verification_code(secret)

      # Confirm setup with valid code
      {:ok, confirmed_user} =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: setup_token, code: code},
          []
        )

      # Secret should now be stored on user
      refute is_nil(confirmed_user.totp_secret)
      assert confirmed_user.totp_secret == secret
    end

    test "confirm_setup with invalid code returns error" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # Setup TOTP
      {:ok, user_with_pending_setup} = Strategy.action(strategy, :setup, %{user: user}, [])
      setup_token = user_with_pending_setup.__metadata__.setup_token

      # Try to confirm with invalid code
      result =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: setup_token, code: "000000"},
          []
        )

      assert {:error, _error} = result

      # Reload user to verify secret was not stored
      {:ok, reloaded_user} =
        Ash.get(Example.UserWithTotpConfirmSetup, user.id, authorize?: false)

      assert is_nil(reloaded_user.totp_secret)
    end

    test "confirm_setup with expired/invalid token returns error" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # Try to confirm with a fake token
      result =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: "invalid_token", code: "123456"},
          []
        )

      assert {:error, _error} = result
    end

    test "setup token cannot be reused after confirmation" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # Setup TOTP
      {:ok, user_with_pending_setup} = Strategy.action(strategy, :setup, %{user: user}, [])
      setup_token = user_with_pending_setup.__metadata__.setup_token
      totp_url = user_with_pending_setup.__metadata__.totp_url

      # Extract secret from TOTP URL
      %URI{query: query} = URI.parse(totp_url)
      %{"secret" => encoded_secret} = URI.decode_query(query)
      secret = Base.decode32!(encoded_secret, padding: false)

      # Generate a valid code
      code = NimbleTOTP.verification_code(secret)

      # First confirmation should succeed
      {:ok, _confirmed_user} =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: setup_token, code: code},
          []
        )

      # Second confirmation with same token should fail (token was revoked)
      result =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: setup_token, code: code},
          []
        )

      assert {:error, _error} = result
    end

    test "sign_in works after confirmation" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # Setup and confirm TOTP
      {:ok, user_with_pending_setup} = Strategy.action(strategy, :setup, %{user: user}, [])
      setup_token = user_with_pending_setup.__metadata__.setup_token
      totp_url = user_with_pending_setup.__metadata__.totp_url

      %URI{query: query} = URI.parse(totp_url)
      %{"secret" => encoded_secret} = URI.decode_query(query)
      secret = Base.decode32!(encoded_secret, padding: false)

      code = NimbleTOTP.verification_code(secret)

      {:ok, _confirmed_user} =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: setup_token, code: code},
          []
        )

      # Generate a new code for sign-in (may need to wait if same code)
      sign_in_code = NimbleTOTP.verification_code(secret)

      # Sign in with the code
      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user.email, "code" => sign_in_code},
          []
        )

      assert signed_in_user.id == user.id
      assert signed_in_user.__metadata__.token
    end
  end

  describe "single-step setup still works" do
    test "setup stores secret directly when confirm_setup_enabled? is false" do
      # Using the regular UserWithTotp which has confirm_setup_enabled? = false
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      # User starts without a TOTP secret
      assert is_nil(user.totp_secret)

      # Setup TOTP - should store secret directly
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Secret should be stored on user
      refute is_nil(user_with_secret.totp_secret)
      assert is_binary(user_with_secret.totp_secret)

      # No setup_token metadata (single-step flow)
      refute Map.has_key?(user_with_secret.__metadata__, :setup_token)
    end
  end
end
