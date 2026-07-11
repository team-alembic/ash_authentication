# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.PlugTest do
  use DataCase, async: false

  import Plug.Test
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

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

    test "includes a spec-compliant user descriptor", %{strategy: strategy} do
      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/registration_challenge", %{
          "email" => "test@example.com"
        })
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.registration_challenge(strategy)

      body = Jason.decode!(conn.resp_body)

      # The user handle is random bytes (max 64 per spec), not derived from PII
      assert {:ok, handle} = Base.url_decode64(body["user"]["id"], padding: false)
      assert byte_size(handle) == 32
      assert body["user"]["name"] == "test@example.com"
      assert body["user"]["displayName"] == "test@example.com"

      # The handle is retained in the session so registration can store it
      session = Plug.Conn.get_session(conn, "webauthn_attestation_challenge_webauthn")
      assert session["user_handle"] || session[:user_handle] == body["user"]["id"]
    end

    test "uses display_name param for the account name in passkey-first flows", %{
      strategy: strategy
    } do
      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/registration_challenge", %{
          "display_name" => "Simon"
        })
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.registration_challenge(strategy)

      body = Jason.decode!(conn.resp_body)
      assert body["user"]["name"] == "Simon"
      assert body["user"]["displayName"] == "Simon"
    end

    test "identity value wins as name, display_name as displayName", %{strategy: strategy} do
      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/registration_challenge", %{
          "email" => "test@example.com",
          "display_name" => "Simon"
        })
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.registration_challenge(strategy)

      body = Jason.decode!(conn.resp_body)
      assert body["user"]["name"] == "test@example.com"
      assert body["user"]["displayName"] == "Simon"
    end

    test "excludes existing credentials when the identity is known", %{strategy: strategy} do
      user =
        Example.UserWithWebAuthn
        |> Ash.Changeset.for_create(:create, %{email: "exclude-test@example.com"})
        |> Ash.create!()

      fixture = WebAuthnFixtures.generate_registration()

      build_webauthn_credential(user, %{
        credential_id: fixture.credential_id,
        public_key: fixture.cose_key
      })

      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/registration_challenge", %{
          "email" => "exclude-test@example.com"
        })
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.registration_challenge(strategy)

      body = Jason.decode!(conn.resp_body)

      assert [%{"id" => encoded_id, "type" => "public-key"}] = body["excludeCredentials"]
      assert Base.url_decode64!(encoded_id, padding: false) == fixture.credential_id
    end

    test "sends no exclusions when no identity is supplied", %{strategy: strategy} do
      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/registration_challenge", %{})
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.registration_challenge(strategy)

      body = Jason.decode!(conn.resp_body)
      assert body["excludeCredentials"] == []
    end

    test "sends no exclusions in passkey-first mode" do
      strategy = Info.strategy!(Example.UserWithWebAuthnNoIdentity, :webauthn)

      conn =
        :get
        |> conn("/user_with_webauthn_no_identity/webauthn/registration_challenge", %{
          "email" => "irrelevant@example.com"
        })
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.registration_challenge(strategy)

      body = Jason.decode!(conn.resp_body)
      assert body["excludeCredentials"] == []
    end

    test "requests the credProps extension", %{strategy: strategy} do
      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/registration_challenge", %{})
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.registration_challenge(strategy)

      body = Jason.decode!(conn.resp_body)
      assert body["extensions"] == %{"credProps" => true}
    end

    test "advertises pubKeyCredParams in preference order", %{strategy: strategy} do
      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/registration_challenge", %{})
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.registration_challenge(strategy)

      body = Jason.decode!(conn.resp_body)
      algs = Enum.map(body["pubKeyCredParams"], & &1["alg"])

      assert [-7, -8 | _] = algs
      assert -257 in algs
      assert Enum.all?(body["pubKeyCredParams"], &(&1["type"] == "public-key"))
      # SHA-1 RSA and ES256K are supported by Wax but deliberately not advertised
      refute -65_535 in algs
      refute -47 in algs
    end
  end

  describe "register/2" do
    test "full round trip: challenge then register", %{strategy: strategy} do
      email = "roundtrip@example.com"

      challenge_conn = registration_challenge_conn(strategy, email)
      body = Jason.decode!(challenge_conn.resp_body)

      register_conn = register_conn(strategy, challenge_conn, email)

      assert {:ok, user} = register_conn.private[:authentication_result]
      assert to_string(user.email) == email

      # The user handle minted at challenge time is persisted on the credential
      {:ok, [credential]} = WebAuthn.Actions.list_credentials(strategy, user, [])

      assert credential.user_handle ==
               Base.url_decode64!(body["user"]["id"], padding: false)
    end

    test "restrictive trusted_attestation_types rejects untrusted attestation", %{
      strategy: strategy
    } do
      # Only accept attestation chaining to a known root; the fixture's
      # "none" attestation must be refused
      strategy = %{strategy | trusted_attestation_types: [:basic, :attca]}
      email = "untrusted@example.com"

      challenge_conn = registration_challenge_conn(strategy, email)
      register_conn = register_conn(strategy, challenge_conn, email)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               register_conn.private[:authentication_result]
    end
  end

  describe "challenge session scoping" do
    test "attestation and authentication challenges use distinct session keys", %{
      strategy: strategy
    } do
      reg_conn =
        :get
        |> conn("/user_with_webauthn/webauthn/registration_challenge", %{})
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.registration_challenge(strategy)

      auth_conn =
        :get
        |> conn("/user_with_webauthn/webauthn/authentication_challenge", %{})
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.authentication_challenge(strategy)

      assert %{} = Plug.Conn.get_session(reg_conn, "webauthn_attestation_challenge_webauthn")
      assert %{} = Plug.Conn.get_session(auth_conn, "webauthn_authentication_challenge_webauthn")

      refute Plug.Conn.get_session(reg_conn, "webauthn_authentication_challenge_webauthn")
      refute Plug.Conn.get_session(auth_conn, "webauthn_attestation_challenge_webauthn")
    end

    test "sign_in neither consumes nor accepts a pending registration challenge", %{
      strategy: strategy
    } do
      reg_conn =
        :get
        |> conn("/user_with_webauthn/webauthn/registration_challenge", %{})
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.registration_challenge(strategy)

      attestation_key = "webauthn_attestation_challenge_webauthn"
      attestation_data = Plug.Conn.get_session(reg_conn, attestation_key)

      # A sign-in arriving in another tab, with only the registration
      # challenge in the session
      sign_in_conn =
        :post
        |> conn("/user_with_webauthn/webauthn/sign_in", %{})
        |> SessionPipeline.call([])
        |> Plug.Conn.put_session(attestation_key, attestation_data)
        |> WebAuthn.Plug.sign_in(strategy)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               sign_in_conn.private[:authentication_result]

      # The pending registration ceremony is untouched
      assert Plug.Conn.get_session(sign_in_conn, attestation_key) == attestation_data
    end
  end

  describe "authentication_challenge/2" do
    test "includes transports hints in allowCredentials when stored", %{strategy: strategy} do
      user =
        Example.UserWithWebAuthn
        |> Ash.Changeset.for_create(:create, %{email: "transports@example.com"})
        |> Ash.create!()

      with_transports = WebAuthnFixtures.generate_registration()
      without_transports = WebAuthnFixtures.generate_registration()

      build_webauthn_credential(user, %{
        credential_id: with_transports.credential_id,
        public_key: with_transports.cose_key,
        transports: ["internal", "hybrid"]
      })

      build_webauthn_credential(user, %{
        credential_id: without_transports.credential_id,
        public_key: without_transports.cose_key
      })

      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/authentication_challenge", %{
          "email" => "transports@example.com"
        })
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.authentication_challenge(strategy)

      body = Jason.decode!(conn.resp_body)
      entries = Map.new(body["allowCredentials"], &{&1["id"], &1})

      hinted = Base.url_encode64(with_transports.credential_id, padding: false)
      unhinted = Base.url_encode64(without_transports.credential_id, padding: false)

      assert entries[hinted]["transports"] == ["internal", "hybrid"]
      refute Map.has_key?(entries[unhinted], "transports")
      assert Enum.all?(Map.values(entries), &(&1["type"] == "public-key"))
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

    test "user descriptor identifies the actor with a stable handle", %{strategy: strategy} do
      {:ok, user} =
        Example.UserWithWebAuthn
        |> Ash.Changeset.for_create(:create, %{email: "handle@example.com"})
        |> Ash.create()

      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/add_credential_challenge", %{})
        |> SessionPipeline.call([])
        |> Ash.PlugHelpers.set_actor(user)
        |> WebAuthn.Plug.add_credential_challenge(strategy)

      body = Jason.decode!(conn.resp_body)

      assert {:ok, handle} = Base.url_decode64(body["user"]["id"], padding: false)
      # No prior credentials, so the handle falls back to the primary key
      assert handle == to_string(user.id)
      assert body["user"]["name"] == "handle@example.com"
    end

    test "reuses the stored handle and excludes existing credentials", %{strategy: strategy} do
      user =
        Example.UserWithWebAuthn
        |> Ash.Changeset.for_create(:create, %{email: "exclude-add@example.com"})
        |> Ash.create!()

      fixture = WebAuthnFixtures.generate_registration()
      stored_handle = :crypto.strong_rand_bytes(32)

      build_webauthn_credential(user, %{
        credential_id: fixture.credential_id,
        public_key: fixture.cose_key,
        user_handle: stored_handle
      })

      conn =
        :get
        |> conn("/user_with_webauthn/webauthn/add_credential_challenge", %{})
        |> SessionPipeline.call([])
        |> Ash.PlugHelpers.set_actor(user)
        |> WebAuthn.Plug.add_credential_challenge(strategy)

      body = Jason.decode!(conn.resp_body)

      assert Base.url_decode64!(body["user"]["id"], padding: false) == stored_handle

      assert [%{"id" => encoded_id, "type" => "public-key"}] = body["excludeCredentials"]
      assert Base.url_decode64!(encoded_id, padding: false) == fixture.credential_id
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

  @attestation_session_key "webauthn_attestation_challenge_webauthn"

  defp registration_challenge_conn(strategy, email) do
    :get
    |> conn("/user_with_web_authn/webauthn/registration_challenge", %{"email" => email})
    |> SessionPipeline.call([])
    |> WebAuthn.Plug.registration_challenge(strategy)
  end

  # Build a register POST that answers the server-issued challenge. The test
  # SessionPipeline mints a fresh secret_key_base per conn, so cookies can't
  # round-trip; the session entry is transplanted instead.
  defp register_conn(strategy, challenge_conn, email) do
    body = Jason.decode!(challenge_conn.resp_body)
    challenge_bytes = Base.url_decode64!(body["challenge"], padding: false)
    session_data = Plug.Conn.get_session(challenge_conn, @attestation_session_key)

    fixture =
      WebAuthnFixtures.generate_registration(
        origin: "http://www.example.com",
        rp_id: "example.com",
        challenge_bytes: challenge_bytes
      )

    :post
    |> conn("/user_with_web_authn/webauthn/register", %{
      "user_with_web_authn" => %{
        "email" => email,
        "attestation_object" => fixture.attestation_object,
        "client_data_json" => fixture.client_data_json,
        "raw_id" => fixture.raw_id
      }
    })
    |> SessionPipeline.call([])
    |> Plug.Conn.put_session(@attestation_session_key, session_data)
    |> WebAuthn.Plug.register(strategy)
  end
end
