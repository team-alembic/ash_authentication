# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.JwtTest do
  @moduledoc false
  use DataCase, async: false
  alias AshAuthentication.Jwt

  describe "default_algorithm/0" do
    test "is a supported algorithm" do
      assert Jwt.default_algorithm() in Jwt.supported_algorithms()
    end
  end

  describe "supported_algorithms/0" do
    test "is a list of algorithms" do
      algorithms = Jwt.supported_algorithms()

      assert Enum.any?(algorithms)

      for algorithm <- algorithms do
        assert is_binary(algorithm)
        assert byte_size(algorithm) > 0
      end
    end
  end

  describe "default_lifetime_hrs/0" do
    test "is a positive integer" do
      assert Jwt.default_lifetime_hrs() > 0
      assert is_integer(Jwt.default_lifetime_hrs())
    end
  end

  describe "token_for_user/3" do
    test "correctly generates and signs tokens" do
      user = build_user()
      assert {:ok, token, claims} = Jwt.token_for_user(user)

      now = DateTime.utc_now() |> DateTime.to_unix()

      assert token =~ ~r/^[\w-]+\.[\w-]+\.[\w-]+$/
      assert {:ok, _} = Version.parse_requirement(claims["aud"])
      assert claims["exp"] > now
      assert_in_delta(claims["iat"], now, 1.5)
      assert claims["iss"] =~ ~r/^AshAuthentication v\d+\.\d+\.\d+$/
      assert claims["jti"] =~ ~r/^[0-9a-z]+$/
      assert_in_delta(claims["nbf"], now, 1.5)
      assert claims["sub"] == "user?id=#{user.id}"
    end

    test "it encodes the tenant when passed one for a multitenant resource" do
      user = build_user_with_multitenancy()
      assert {:ok, _token, claims} = Jwt.token_for_user(user, %{})
      assert claims["tenant"] == user.organisation_id
    end

    test "it encodes tenant as nil when not passed one for a multitenant resource" do
      user = build_user_with_multitenancy(organisation_id: nil)
      assert {:ok, _token, claims} = Jwt.token_for_user(user, %{})
      assert Map.has_key?(claims, "tenant")
      assert claims["tenant"] == nil
    end

    test "it doesn't encode the tenant otherwise" do
      user = build_user()
      assert {:ok, _token, claims} = Jwt.token_for_user(user, %{})
      refute is_map_key(claims, "tenant")
    end
  end

  describe "verify/2" do
    test "it is successful when given a valid token and the correct otp app" do
      {:ok, token, actual_claims} = build_user() |> Jwt.token_for_user()

      assert {:ok, validated_claims, resource} = Jwt.verify(token, :ash_authentication)
      assert validated_claims == actual_claims
      assert resource == Example.User
    end

    test "it is unsuccessful when the token signature isn't correct" do
      {:ok, token, _} = build_user() |> Jwt.token_for_user()

      # mangle the token.
      [header, payload, signature] = String.split(token, ".")
      token = [header, payload, String.reverse(signature)] |> Enum.join(".")

      assert :error = Jwt.verify(token, :ash_authentication)
    end

    test "it is unsuccessful when the token has been revoked" do
      {:ok, token, _} = build_user() |> Jwt.token_for_user()

      AshAuthentication.TokenResource.revoke(Example.Token, token)

      assert :error = Jwt.verify(token, :ash_authentication)
    end
  end
end
