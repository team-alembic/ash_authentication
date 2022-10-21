defmodule AshAuthentication.Jwt.ConfigTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Mimic
  alias AshAuthentication.{Jwt.Config, TokenRevocation}

  describe "default_claims/1" do
    test "it is a token config" do
      claims = Config.default_claims(Example.UserWithUsername)
      assert is_map(claims)

      assert Enum.all?(claims, fn {name, config} ->
               assert is_binary(name)
               assert is_struct(config, Joken.Claim)
             end)
    end
  end

  describe "generate_issuer/1" do
    test "it correctly generates" do
      assert "AshAuthentication v1.2.3" = Config.generate_issuer(Version.parse!("1.2.3"))
    end
  end

  describe "validate_issuer/3" do
    test "is true when the issuer starts with \"AshAuthentication\"" do
      assert Config.validate_issuer("AshAuthentication foo", nil, nil)
    end

    test "is false otherwise" do
      garbage = 2 |> Faker.Lorem.words() |> Enum.join(" ")
      refute Config.validate_issuer(garbage, nil, nil)
    end
  end

  describe "generate_audience/1" do
    test "it correctly generates" do
      assert "~> 1.2" = Config.generate_audience(Version.parse!("1.2.3"))
    end
  end

  describe "validate_audience/4" do
    test "is true when the decoding version meets the minimum requirement" do
      assert Config.validate_audience("~> 1.2", nil, nil, Version.parse!("1.2.3"))
    end

    test "is false otherwise" do
      refute Config.validate_audience("~> 1.2", nil, nil, Version.parse!("1.1.2"))
    end
  end

  describe "validate_jti/3" do
    test "is true when the token has not been revoked" do
      TokenRevocation
      |> stub(:revoked?, fn _, _ -> false end)

      assert Config.validate_jti("fake jti", nil, %{resource: Example.UserWithUsername})
    end

    test "is false when the token has been revoked" do
      TokenRevocation
      |> stub(:revoked?, fn _, _ -> true end)

      assert Config.validate_jti("fake jti", nil, %{resource: Example.UserWithUsername})
    end
  end

  describe "token_signer/1" do
    test "it returns a signer configuration" do
      assert %Joken.Signer{} = Config.token_signer(Example.UserWithUsername)
    end
  end
end
