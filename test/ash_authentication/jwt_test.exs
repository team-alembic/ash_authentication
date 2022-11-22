defmodule AshAuthentication.JwtTest do
  @moduledoc false
  use DataCase, async: true
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

  describe "token_for_user/1" do
    test "correctly generates and signs tokens" do
      user = build_user()
      assert {:ok, token, claims} = Jwt.token_for_user(user)

      now = DateTime.utc_now() |> DateTime.to_unix()

      assert token =~ ~r/^[\w-]+\.[\w-]+\.[\w-]+$/
      assert {:ok, _} = Version.parse_requirement(claims["aud"])
      assert claims["exp"] > now
      assert_in_delta(claims["iat"], now, 1.5)
      assert claims["iss"] =~ ~r/^AshAuthentication v\d\.\d\.\d$/
      assert claims["jti"] =~ ~r/^[0-9a-z]+$/
      assert_in_delta(claims["nbf"], now, 1.5)
      assert claims["sub"] == "user?id=#{user.id}"
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

      AshAuthentication.TokenRevocation.revoke(Example.TokenRevocation, token)

      assert :error = Jwt.verify(token, :ash_authentication)
    end
  end
end
