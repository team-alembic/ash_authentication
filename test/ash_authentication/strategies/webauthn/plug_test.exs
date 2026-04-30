defmodule AshAuthentication.Strategy.WebAuthn.PlugTest do
  use DataCase, async: false

  import Plug.Test
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn

  setup do
    strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)
    %{strategy: strategy}
  end

  describe "registration_challenge/2" do
    test "returns challenge as JSON", %{strategy: strategy} do
      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/registration_challenge", %{
          "email" => "test@example.com"
        })
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.registration_challenge(strategy)

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert is_binary(body["challenge"])
      assert body["rp"]["id"] == "example.com"
    end
  end

  describe "add_credential_challenge/2" do
    test "returns 401-style failure when no actor is present", %{strategy: strategy} do
      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/add_credential_challenge", %{})
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.add_credential_challenge(strategy)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               conn.private[:authentication_result]
    end

    test "returns a challenge when actor is present", %{strategy: strategy} do
      {:ok, user} =
        Example.UserWithWebAuthn
        |> Ash.Changeset.for_create(:create, %{email: "add@example.com"})
        |> Ash.create()

      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/add_credential_challenge", %{})
        |> SessionPipeline.call([])
        |> Ash.PlugHelpers.set_actor(user)
        |> WebAuthn.Plug.add_credential_challenge(strategy)

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert is_binary(body["challenge"])
    end
  end

  describe "add_credential/2" do
    test "fails when no actor is present", %{strategy: strategy} do
      conn =
        :post
        |> conn("/user_with_webauthn/webauthn/add_credential", %{})
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.add_credential(strategy)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               conn.private[:authentication_result]
    end
  end
end
