defmodule AshAuthenticationTest do
  @moduledoc false
  use ExUnit.Case
  doctest AshAuthentication

  describe "authenticated_resources/0" do
    test "it correctly locates all authenticatable resources" do
      assert [
               %{
                 api: Example,
                 providers: providers,
                 resource: Example.UserWithUsername,
                 subject_name: :user_with_username
               }
             ] = AshAuthentication.authenticated_resources(:ash_authentication)

      assert AshAuthentication.PasswordAuthentication in providers
      assert AshAuthentication.PasswordReset in providers
    end
  end
end
