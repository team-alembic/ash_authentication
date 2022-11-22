defmodule AshAuthentication.TokenRevocationTest do
  @moduledoc false
  use DataCase, async: true
  import AshAuthentication.TokenRevocation
  alias AshAuthentication.{Jwt, TokenRevocation}
  doctest AshAuthentication.TokenRevocation

  describe "revoke/2" do
    test "it revokes tokens" do
      {token, %{"jti" => jti}} = build_token()
      refute TokenRevocation.revoked?(Example.TokenRevocation, jti)

      assert :ok = TokenRevocation.revoke(Example.TokenRevocation, token)

      assert TokenRevocation.revoked?(Example.TokenRevocation, jti)
    end
  end

  def build_token do
    {:ok, token, claims} =
      build_user()
      |> Jwt.token_for_user()

    {token, claims}
  end
end
