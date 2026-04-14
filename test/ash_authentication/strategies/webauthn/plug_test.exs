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
end
