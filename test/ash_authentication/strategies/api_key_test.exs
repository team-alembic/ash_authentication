# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.ApiKeyTest do
  @moduledoc false
  use DataCase, async: true

  import Plug.Test
  import Plug.Conn, only: [put_req_header: 3]

  alias AshAuthentication.Strategy.ApiKey.Plug, as: ApiKeyPlug

  alias Example.{ApiKey, User}

  setup do
    # Create a user with password
    user = build_user()

    # Create an API key for the user
    api_key =
      ApiKey
      |> Ash.Changeset.for_create(
        :create,
        %{
          user_id: user.id
        },
        authorize?: false
      )
      |> Ash.create!()

    %{user: user, api_key: api_key, plaintext_api_key: api_key.__metadata__.plaintext_api_key}
  end

  describe "signing in with API key" do
    test "succeeds with valid API key", %{
      user: user,
      plaintext_api_key: plaintext_api_key
    } do
      result =
        User
        |> Ash.Query.for_read(:sign_in_with_api_key, %{api_key: plaintext_api_key},
          context: %{
            private: %{ash_authentication?: true}
          }
        )
        |> Ash.read_one()

      assert {:ok, auth_user} = result
      assert %ApiKey{} = auth_user.__metadata__.api_key
      assert auth_user.id == user.id
      assert auth_user.username == user.username
    end

    test "returns no user with invalid API key" do
      refute User
             |> Ash.Query.for_read(:sign_in_with_api_key, %{api_key: "invalid_api_key"})
             |> Ash.read_one!()
    end
  end

  describe "authentication with API key using plug" do
    test "succeeeds when API key is present in header", %{
      plaintext_api_key: plaintext_api_key,
      user: user
    } do
      opts = ApiKeyPlug.init(resource: Example.User, source: :header)

      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Bearer #{plaintext_api_key}")
        |> ApiKeyPlug.call(opts)

      assert conn.assigns.current_user.id == user.id
    end

    test "succeeds when API key is present in query parameter", %{
      plaintext_api_key: plaintext_api_key,
      user: user
    } do
      opts = ApiKeyPlug.init(resource: Example.User, source: :query_param)

      conn =
        :get
        |> conn("/?api_key=#{plaintext_api_key}")
        |> Plug.Conn.fetch_query_params()
        |> ApiKeyPlug.call(opts)

      assert conn.assigns.current_user.id == user.id
    end

    test "succeeds with custom query parameter name", %{
      plaintext_api_key: plaintext_api_key,
      user: user
    } do
      opts = ApiKeyPlug.init(resource: Example.User, source: :query_param, param_name: "token")

      conn =
        :get
        |> conn("/?token=#{plaintext_api_key}")
        |> Plug.Conn.fetch_query_params()
        |> ApiKeyPlug.call(opts)

      assert conn.assigns.current_user.id == user.id
    end

    test "succeeds with custom header prefix", %{plaintext_api_key: plaintext_api_key, user: user} do
      opts = ApiKeyPlug.init(resource: Example.User, source: :header, header_prefix: "Token ")

      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Token #{plaintext_api_key}")
        |> ApiKeyPlug.call(opts)

      assert conn.assigns.current_user.id == user.id
    end

    test "succeeds with header_or_query_param using header", %{
      plaintext_api_key: plaintext_api_key,
      user: user
    } do
      opts = ApiKeyPlug.init(resource: Example.User, source: :header_or_query_param)

      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Bearer #{plaintext_api_key}")
        |> ApiKeyPlug.call(opts)

      assert conn.assigns.current_user.id == user.id
    end

    test "succeeds with header_or_query_param using query parameter", %{
      plaintext_api_key: plaintext_api_key,
      user: user
    } do
      opts = ApiKeyPlug.init(resource: Example.User, source: :header_or_query_param)

      conn =
        :get
        |> conn("/?api_key=#{plaintext_api_key}")
        |> Plug.Conn.fetch_query_params()
        |> ApiKeyPlug.call(opts)

      assert conn.assigns.current_user.id == user.id
    end

    test "uses custom assign name when provided", %{
      plaintext_api_key: plaintext_api_key,
      user: user
    } do
      opts = ApiKeyPlug.init(resource: Example.User, source: :header, assign: :authenticated_user)

      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Bearer #{plaintext_api_key}")
        |> ApiKeyPlug.call(opts)

      assert conn.assigns.authenticated_user.id == user.id
    end

    test "fails with invalid API key in header" do
      opts = ApiKeyPlug.init(resource: Example.User, source: :header)

      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Bearer invalid_key")
        |> ApiKeyPlug.call(opts)

      assert conn.status == 401
      assert conn.resp_body == "Unauthorized"
      assert conn.halted
    end

    test "fails with missing API key when required" do
      opts = ApiKeyPlug.init(resource: Example.User, source: :header, required?: true)

      conn =
        :get
        |> conn("/")
        |> ApiKeyPlug.call(opts)

      assert conn.status == 401
      assert conn.resp_body == "Unauthorized"
      assert conn.halted
    end

    test "doesn't fail with missing API key when not required" do
      opts = ApiKeyPlug.init(resource: Example.User, source: :header, required?: false)

      conn =
        :get
        |> conn("/")
        |> ApiKeyPlug.call(opts)

      refute conn.halted
      refute Map.has_key?(conn.assigns, :current_user)
    end

    test "returns JSON error when Accept header contains 'json'" do
      opts = ApiKeyPlug.init(resource: Example.User, source: :header)

      conn =
        :get
        |> conn("/")
        |> put_req_header("accept", "application/json")
        |> ApiKeyPlug.call(opts)

      assert conn.status == 401
      assert conn.resp_body == ~s({"error":"Unauthorized"})

      assert Plug.Conn.get_resp_header(conn, "content-type") == [
               "application/json; charset=utf-8"
             ]

      assert conn.halted
    end

    test "uses custom error handler when provided" do
      custom_error_handler = fn conn, _error ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(401, ~s({"message":"Custom error"}))
        |> Plug.Conn.halt()
      end

      opts =
        ApiKeyPlug.init(
          resource: Example.User,
          source: :header,
          on_error: custom_error_handler
        )

      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Bearer invalid_key")
        |> ApiKeyPlug.call(opts)

      assert conn.status == 401
      assert conn.resp_body == ~s({"message":"Custom error"})

      assert Plug.Conn.get_resp_header(conn, "content-type") == [
               "application/json; charset=utf-8"
             ]

      assert conn.halted
    end

    test "handles invalid header prefix correctly" do
      opts = ApiKeyPlug.init(resource: Example.User, source: :header)

      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Token invalid_prefix")
        |> ApiKeyPlug.call(opts)

      assert conn.status == 401
      assert conn.resp_body == "Unauthorized"
      assert conn.halted
    end

    test "properly sets actor on the connection", %{
      plaintext_api_key: plaintext_api_key,
      user: user
    } do
      opts = ApiKeyPlug.init(resource: Example.User, source: :header)

      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Bearer #{plaintext_api_key}")
        |> ApiKeyPlug.call(opts)

      assert conn.assigns.current_user.id == user.id
      assert Ash.PlugHelpers.get_actor(conn) == conn.assigns.current_user
    end
  end

  describe "API key lifecycle" do
    test "user can have multiple API keys", %{user: user, plaintext_api_key: plaintext_api_key} do
      api_key2 =
        ApiKey
        |> Ash.Changeset.for_create(
          :create,
          %{
            user_id: user.id
          },
          authorize?: false
        )
        |> Ash.create!()

      plaintext_api_key2 = api_key2.__metadata__.plaintext_api_key

      # Both keys should work for authentication
      {:ok, _} =
        User
        |> Ash.Query.for_read(:sign_in_with_api_key, %{api_key: plaintext_api_key},
          context: %{
            private: %{ash_authentication?: true}
          }
        )
        |> Ash.read_one()

      {:ok, _} =
        User
        |> Ash.Query.for_read(:sign_in_with_api_key, %{api_key: plaintext_api_key2},
          context: %{
            private: %{ash_authentication?: true}
          }
        )
        |> Ash.read_one()
    end

    test "deleting API key prevents authentication", %{
      user: user,
      api_key: api_key,
      plaintext_api_key: plaintext_api_key
    } do
      # Delete the API key
      api_key
      |> Ash.Changeset.for_destroy(:destroy, %{}, authorize?: false)
      |> Ash.destroy!()

      # Should no longer be able to authenticate with that key
      refute User
             |> Ash.Query.for_read(:sign_in_with_api_key, %{api_key: plaintext_api_key})
             |> Ash.read_one!()

      # But can still authenticate with password
      {:ok, _} =
        User
        |> Ash.Query.for_read(:sign_in_with_password, %{
          username: user.username,
          password: user.__metadata__.password
        })
        |> Ash.read_one()
    end
  end

  describe "fallback to other authentication methods" do
    test "can still use password authentication when API keys exist", %{user: user} do
      result =
        User
        |> Ash.Query.for_read(:sign_in_with_password, %{
          username: user.username,
          password: user.__metadata__.password
        })
        |> Ash.read_one()

      assert {:ok, auth_user} = result
      assert auth_user.id == user.id
    end

    test "invalid password still fails authentication", %{user: user} do
      assert_raise Ash.Error.Forbidden, fn ->
        User
        |> Ash.Query.for_read(:sign_in_with_password, %{
          username: user.username,
          password: "wrong_password"
        })
        |> Ash.read_one!()
      end
    end
  end
end
