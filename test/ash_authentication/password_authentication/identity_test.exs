defmodule AshAuthentication.IdentityTest do
  @moduledoc false
  use AshAuthentication.DataCase, async: true
  alias Ash.Error
  alias AshAuthentication.{PasswordAuthentication, PasswordAuthentication.Info}

  describe "sign_in_action/2" do
    @describetag resource: Example.UserWithUsername
    setup :resource_config

    test "when provided invalid credentials", %{resource: resource, config: config} do
      assert {:error, error} =
               PasswordAuthentication.sign_in_action(resource, %{
                 config.identity_field => username(),
                 config.password_field => password()
               })

      assert Error.error_messages(error.errors, "", false) =~ "Authentication failed"
    end

    test "when provided valid credentials", %{resource: resource, config: config} do
      username = username()
      password = password()

      {:ok, expected} =
        PasswordAuthentication.register_action(resource, %{
          config.identity_field => username,
          config.password_field => password,
          config.password_confirmation_field => password
        })

      assert {:ok, actual} =
               PasswordAuthentication.sign_in_action(resource, %{
                 config.identity_field => username,
                 config.password_field => password
               })

      assert actual.id == expected.id
    end
  end

  defp resource_config(%{resource: resource}) do
    config =
      resource
      |> Info.password_authentication_options()

    {:ok, config: config}
  end
end
