defmodule AshAuthentication.JsonWebTokenTest do
  @moduledoc false
  use AshAuthentication.DataCase, async: true
  alias AshAuthentication.JsonWebToken

  test "tokens are generated correctly" do
    signer = JsonWebToken.token_signer()
    additional_claim = 9999 |> :rand.uniform() |> to_string()

    assert {:ok, token, claims} =
             JsonWebToken.generate_and_sign(%{"test" => additional_claim}, signer)

    assert {:ok, _} =
             token
             |> String.split(".")
             |> hd()
             |> Base.decode64()

    assert {:ok, %{"test" => ^additional_claim}} = JsonWebToken.verify_and_validate(token, signer)

    expected_expiry_time =
      DateTime.utc_now()
      |> DateTime.add(JsonWebToken.token_lifetime())
      |> DateTime.to_unix()

    actual_expiry_time =
      claims
      |> Map.fetch!("exp")

    assert_in_delta(expected_expiry_time, actual_expiry_time, 1)

    assert Map.fetch!(claims, "iss") =~ ~r/^AshAuthentication v\d+\.\d+\.\d+$/

    assert Map.fetch!(claims, "aud") =~ ~r/^~> \d+\.\d+$/
  end

  describe "token_lifetime/0..1" do
    test "it returns the configured lifetime converted to seconds when one is present" do
      assert 3 * 60 * 60 == JsonWebToken.token_lifetime(token_lifetime: 3)
    end

    test "it returns the default lifetime converted to seconds when one is present" do
      assert 7 * 24 * 60 * 60 == JsonWebToken.token_lifetime()
    end
  end

  describe "token_signer/0..1" do
    test "when there is no signing secret configured, it raises an error" do
      assert_raise(RuntimeError, ~r/missing.*signing secret/i, fn ->
        JsonWebToken.token_signer([])
      end)
    end

    test "when there is no signing algorithm it uses the default" do
      assert %{alg: "HS256"} = JsonWebToken.token_signer(signing_secret: "Hi Bob")
    end
  end
end
