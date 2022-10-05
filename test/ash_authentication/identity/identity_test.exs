defmodule AshAuthentication.IdentityTest do
  @moduledoc false
  use AshAuthentication.DataCase, async: true
  alias Ash.Error
  alias AshAuthentication.{Identity, Identity.Config}

  describe "sign_in_action/2" do
    @describetag resource: Example.UserWithUsername
    setup :resource_config

    test "when provided invalid credentials", %{resource: resource, config: config} do
      assert {:error, error} =
               Identity.sign_in_action(resource, %{
                 config.identity_field => username(),
                 config.password_field => password()
               })

      assert Error.error_messages(error.errors, "", false) =~ "Authentication failed"
    end

    test "when provided valid credentials", %{resource: resource, config: config} do
      username = username()
      password = password()

      {:ok, expected} =
        Identity.register_action(resource, %{
          config.identity_field => username,
          config.password_field => password,
          config.password_confirmation_field => password
        })

      assert {:ok, actual} =
               Identity.sign_in_action(resource, %{
                 config.identity_field => username,
                 config.password_field => password
               })

      assert actual.id == expected.id
    end
  end

  defp resource_config(%{resource: resource}) do
    config =
      resource
      |> Config.options()

    {:ok, config: config}
  end
end
