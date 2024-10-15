defmodule AshAuthenticationTest do
  @moduledoc false
  use DataCase, async: true
  import AshAuthentication
  doctest AshAuthentication

  describe "authenticated_resources/0" do
    test "it correctly locates all authenticatable resources" do
      assert [Example.User, Example.UserWithTokenRequired, Example.UserWithRegisterMagicLink] =
               authenticated_resources(:ash_authentication)
    end
  end
end
