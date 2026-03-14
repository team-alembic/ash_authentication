# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OtpTest do
  @moduledoc false
  use DataCase, async: true

  import ExUnit.CaptureLog
  import Plug.Test

  alias AshAuthentication.{Info, Plug.Helpers, Strategy, Strategy.Otp}

  describe "compute_deterministic_jti/3" do
    test "is deterministic" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)
      subject = "user_with_otp?id=abc-123"

      jti1 = Otp.compute_deterministic_jti(strategy, subject, "ABCDEF")
      jti2 = Otp.compute_deterministic_jti(strategy, subject, "ABCDEF")

      assert jti1 == jti2
    end

    test "varies with different OTP codes" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)
      subject = "user_with_otp?id=abc-123"

      jti1 = Otp.compute_deterministic_jti(strategy, subject, "ABCDEF")
      jti2 = Otp.compute_deterministic_jti(strategy, subject, "GHIJKL")

      assert jti1 != jti2
    end

    test "varies with different subjects" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      jti1 = Otp.compute_deterministic_jti(strategy, "user_with_otp?id=111", "ABCDEF")
      jti2 = Otp.compute_deterministic_jti(strategy, "user_with_otp?id=222", "ABCDEF")

      assert jti1 != jti2
    end
  end

  describe "normalize_otp/2" do
    test "normalizes to uppercase and trims whitespace" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      assert Otp.normalize_otp(strategy, "  abcdef  ") == "ABCDEF"
      assert Otp.normalize_otp(strategy, "AbCdEf") == "ABCDEF"
    end
  end

  describe "request action" do
    test "sends OTP to existing user" do
      user = build_user_with_otp()
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      log =
        capture_log(fn ->
          assert :ok =
                   Strategy.action(strategy, :request, %{
                     "email" => to_string(user.email)
                   })
        end)

      assert log =~ "OTP request for"
      assert log =~ "code"
    end

    test "returns :ok for non-existent user (does not reveal existence)" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      log =
        capture_log(fn ->
          assert :ok =
                   Strategy.action(strategy, :request, %{
                     "email" => "nonexistent@example.com"
                   })
        end)

      refute log =~ "OTP request for"
    end
  end

  describe "sign_in action" do
    test "succeeds with valid OTP and identity" do
      user = build_user_with_otp()
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      otp_code = extract_otp_code(strategy, user)

      assert {:ok, signed_in_user} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => to_string(user.email),
                 "otp" => otp_code
               })

      assert signed_in_user.id == user.id
      assert signed_in_user.__metadata__[:token]
    end

    test "fails with wrong OTP" do
      user = build_user_with_otp()
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      # Request a valid OTP first so there's a token stored
      _otp_code = extract_otp_code(strategy, user)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => to_string(user.email),
                 "otp" => "ZZZZZZ"
               })
    end

    test "fails for non-existent user" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => "nonexistent@example.com",
                 "otp" => "ABCDEF"
               })
    end

    test "single use: second attempt with same OTP fails" do
      user = build_user_with_otp()
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      otp_code = extract_otp_code(strategy, user)

      assert {:ok, _user} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => to_string(user.email),
                 "otp" => otp_code
               })

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => to_string(user.email),
                 "otp" => otp_code
               })
    end

    test "case-insensitive: lowercase OTP matches uppercase" do
      user = build_user_with_otp()
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      otp_code = extract_otp_code(strategy, user)

      assert {:ok, signed_in_user} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => to_string(user.email),
                 "otp" => String.downcase(otp_code)
               })

      assert signed_in_user.id == user.id
    end
  end

  describe "plug integration" do
    test "request plug" do
      user = build_user_with_otp()
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      log =
        capture_log(fn ->
          conn =
            conn(
              :post,
              "/user_with_otp/otp/request",
              %{"user_with_otp" => %{"email" => to_string(user.email)}}
            )

          conn = Strategy.plug(strategy, :request, conn)
          {_conn, result} = Helpers.get_authentication_result(conn)
          assert result == {:ok, nil}
        end)

      assert log =~ "OTP request for"
    end

    test "sign_in plug" do
      user = build_user_with_otp()
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      otp_code = extract_otp_code(strategy, user)

      conn =
        conn(
          :post,
          "/user_with_otp/otp/sign_in",
          %{
            "user_with_otp" => %{
              "email" => to_string(user.email),
              "otp" => otp_code
            }
          }
        )

      conn = Strategy.plug(strategy, :sign_in, conn)

      {_conn, {:ok, signed_in_user}} =
        Helpers.get_authentication_result(conn)

      assert signed_in_user.id == user.id
    end
  end

  describe "strategy protocol" do
    test "phases" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)
      assert Strategy.phases(strategy) == [:request, :sign_in]
    end

    test "actions" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)
      assert Strategy.actions(strategy) == [:request, :sign_in]
    end

    test "tokens_required?" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)
      assert Strategy.tokens_required?(strategy) == true
    end

    test "routes" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)
      routes = Strategy.routes(strategy)

      assert {"/user_with_otp/otp/request", :request} in routes
      assert {"/user_with_otp/otp/sign_in", :sign_in} in routes
    end

    test "method_for_phase" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)
      assert Strategy.method_for_phase(strategy, :request) == :post
      assert Strategy.method_for_phase(strategy, :sign_in) == :post
    end
  end

  describe "registration enabled" do
    test "registers a new user via OTP" do
      strategy = Info.strategy!(Example.UserWithRegisterOtp, :otp)
      email = "test_#{System.unique_integer([:positive])}@example.com"

      otp_code = extract_otp_code_for_email(strategy, email)

      assert {:ok, user} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => email,
                 "otp" => otp_code
               })

      assert to_string(user.email) == email
      assert user.__metadata__[:token]
    end

    test "signs in existing user via OTP with registration enabled" do
      strategy = Info.strategy!(Example.UserWithRegisterOtp, :otp)
      email = "test_#{System.unique_integer([:positive])}@example.com"

      # First sign-in creates the user
      otp_code = extract_otp_code_for_email(strategy, email)

      assert {:ok, user} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => email,
                 "otp" => otp_code
               })

      # Second sign-in finds the existing user (upsert)
      otp_code2 = extract_otp_code_for_email(strategy, email)

      assert {:ok, user2} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => email,
                 "otp" => otp_code2
               })

      assert user2.id == user.id
    end

    test "fails with invalid OTP code for new user" do
      strategy = Info.strategy!(Example.UserWithRegisterOtp, :otp)
      email = "test_#{System.unique_integer([:positive])}@example.com"

      # Request OTP so a token is stored
      _otp_code = extract_otp_code_for_email(strategy, email)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => email,
                 "otp" => "ZZZZZZ"
               })
    end

    test "sends OTP for non-existent user when registration enabled" do
      strategy = Info.strategy!(Example.UserWithRegisterOtp, :otp)

      log =
        capture_log(fn ->
          assert :ok =
                   Strategy.action(strategy, :request, %{
                     "email" => "brand_new@example.com"
                   })
        end)

      assert log =~ "OTP request for"
      assert log =~ "brand_new@example.com"
    end
  end

  # Helpers

  defp build_user_with_otp(attrs \\ []) do
    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:email, "test_#{System.unique_integer([:positive])}@example.com")

    Example.UserWithOtp
    |> Ash.Changeset.new()
    |> Ash.Changeset.for_create(:create, attrs)
    |> Ash.create!()
  end

  defp extract_otp_code(strategy, user) do
    extract_otp_code_for_email(strategy, to_string(user.email))
  end

  defp extract_otp_code_for_email(strategy, email) do
    log =
      capture_log(fn ->
        Strategy.action(strategy, :request, %{"email" => email})
      end)

    log
    |> String.split("code \"", parts: 2)
    |> Enum.at(1)
    |> String.split("\"", parts: 2)
    |> Enum.at(0)
  end
end
