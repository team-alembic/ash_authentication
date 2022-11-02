defmodule AshAuthentication.PasswordAuthentication.ActionTest do
  @moduledoc false
  use AshAuthentication.DataCase, async: true
  alias Ash.{Changeset, Query}
  alias AshAuthentication.PasswordAuthentication.Info

  describe "register action" do
    @describetag resource: Example.UserWithUsername
    setup :resource_config

    test "password confirmation is verified", %{config: config, resource: resource} do
      assert {:error, error} =
               resource
               |> Changeset.for_create(:register, %{
                 config.identity_field => username(),
                 config.password_field => password(),
                 config.password_confirmation_field => password()
               })
               |> Example.create()

      assert Exception.message(error) =~ "#{config.password_confirmation_field}: does not match"
    end

    test "users can be created", %{config: config, resource: resource} do
      password = password()

      attrs = %{
        config.identity_field => username(),
        config.password_field => password,
        config.password_confirmation_field => password
      }

      assert {:ok, user} =
               resource
               |> Changeset.for_create(:register, attrs)
               |> Example.create()

      refute is_nil(user.id)

      created_username = user |> Map.fetch!(config.identity_field) |> to_string()

      assert created_username == Map.get(attrs, config.identity_field)
    end

    test "the password is hashed correctly", %{config: config, resource: resource} do
      password = password()

      assert user =
               resource
               |> Changeset.for_create(:register, %{
                 config.identity_field => username(),
                 config.password_field => password,
                 config.password_confirmation_field => password
               })
               |> Example.create!()

      assert {:ok, hashed} = Map.fetch(user, config.hashed_password_field)
      assert hashed != password

      assert config.hash_provider.valid?(password, hashed)
    end
  end

  describe "sign_in action" do
    @describetag resource: Example.UserWithUsername
    setup :resource_config

    test "when the user doesn't exist, it returns an empty result", %{
      config: config,
      resource: resource
    } do
      assert {:error, _} =
               resource
               |> Query.for_read(:sign_in, %{
                 config.identity_field => username(),
                 config.password_field => password()
               })
               |> Example.read()
    end

    test "when the user exists, but the password is incorrect, it returns an empty result", %{
      config: config,
      resource: resource
    } do
      username = username()
      password = password()

      resource
      |> Changeset.for_create(:register, %{
        config.identity_field => username,
        config.password_field => password,
        config.password_confirmation_field => password
      })
      |> Example.create!()

      assert {:error, _} =
               resource
               |> Query.for_read(:sign_in, %{
                 config.identity_field => username,
                 config.password_field => password()
               })
               |> Example.read()
    end

    test "when the user exists, and the password is correct, it returns the user", %{
      config: config,
      resource: resource
    } do
      username = username()
      password = password()

      expected =
        resource
        |> Changeset.for_create(:register, %{
          config.identity_field => username,
          config.password_field => password,
          config.password_confirmation_field => password
        })
        |> Example.create!()

      assert {:ok, [actual]} =
               resource
               |> Query.for_read(:sign_in, %{
                 config.identity_field => username,
                 config.password_field => password
               })
               |> Example.read()

      assert actual.id == expected.id
    end

    test "when the user exists, and the password is correct it generates a token", %{
      config: config,
      resource: resource
    } do
      username = username()
      password = password()

      resource
      |> Changeset.for_create(:register, %{
        config.identity_field => username,
        config.password_field => password,
        config.password_confirmation_field => password
      })
      |> Example.create!()

      assert {:ok, [user]} =
               resource
               |> Query.for_read(:sign_in, %{
                 config.identity_field => username,
                 config.password_field => password
               })
               |> Example.read()

      assert is_binary(user.__metadata__.token)
    end
  end

  defp resource_config(%{resource: resource}) do
    config =
      resource
      |> Info.password_authentication_options()

    {:ok, config: config}
  end
end
