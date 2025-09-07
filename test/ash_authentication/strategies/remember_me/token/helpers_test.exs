defmodule AshAuthentication.Strategy.RememberMe.Token.HelpersTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.Strategy.RememberMe.Token.Helpers

  describe "revoke_remember_me_token/3" do
    test "successfully revokes a valid remember me token" do
      user = build_user_with_remember_me()
      {:ok, token} = generate_remember_me_token(user)

      refute AshAuthentication.TokenResource.token_revoked?(Example.Token, token)
      assert :ok = Helpers.revoke_remember_me_token(token, :ash_authentication)
      assert AshAuthentication.TokenResource.token_revoked?(Example.Token, token)
    end
  end
end
