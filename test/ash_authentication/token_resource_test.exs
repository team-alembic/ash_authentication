defmodule AshAuthentication.TokenResourceTest do
  @moduledoc false
  use DataCase, async: true
  alias AshAuthentication.{Jwt, TokenResource}
  doctest AshAuthentication.TokenResource

  describe "revoke/2" do
    test "it revokes tokens" do
      {token, %{"jti" => jti}} = build_token()
      refute TokenResource.jti_revoked?(Example.Token, jti)

      assert :ok = TokenResource.revoke(Example.Token, token)

      assert TokenResource.jti_revoked?(Example.Token, jti)
    end
  end

  def build_token do
    {:ok, token, claims} =
      build_user()
      |> Jwt.token_for_user()

    {token, claims}
  end
end
