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
      assert (session["user_handle"] || session[:user_handle]) == body["user"]["id"]
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

    test "never leaks existing credentials, even when the identity is known", %{
      strategy: strategy
    } do
      # The registration_challenge endpoint is public and unauthenticated.
      # Populating `excludeCredentials` from the submitted identity would turn it
      # into an enumeration oracle leaking a user's real credential ids, so it is
      # always empty regardless of whether the account (or a credential) exists.
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

      assert body["excludeCredentials"] == []
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

    # A client may answer any conveyance preference with a "none" statement
    # (synced passkeys always do); whether that's acceptable is
    # `trusted_attestation_types`' call, not the conveyance preference's.
    for conveyance <- ["direct", "indirect", "enterprise"] do
      test "attestation #{inspect(conveyance)} requests that conveyance and accepts a \"none\" statement",
           %{strategy: strategy} do
        strategy = %{strategy | attestation: unquote(conveyance)}
        email = "attestation-#{unquote(conveyance)}@example.com"

        challenge_conn = registration_challenge_conn(strategy, email)
        assert Jason.decode!(challenge_conn.resp_body)["attestation"] == unquote(conveyance)

        register_conn = register_conn(strategy, challenge_conn, email)
        assert {:ok, _user} = register_conn.private[:authentication_result]
      end

      test "attestation #{inspect(conveyance)} still refuses a \"none\" statement the trusted types exclude",
           %{strategy: strategy} do
        strategy = %{
          strategy
          | attestation: unquote(conveyance),
            trusted_attestation_types: [:basic, :attca]
        }

        email = "attestation-#{unquote(conveyance)}-untrusted@example.com"

        challenge_conn = registration_challenge_conn(strategy, email)
        register_conn = register_conn(strategy, challenge_conn, email)

        assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
                 register_conn.private[:authentication_result]
      end
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

  describe "sign_in/2" do
    test "full round trip: challenge then sign in", %{strategy: strategy} do
      email = "sign-in@example.com"
      passkey = register_passkey(strategy, email)

      challenge_conn = authentication_challenge_conn(strategy, email)
      conn = sign_in_conn(strategy, challenge_conn, email, passkey, sign_count: 1)

      assert {:ok, user} = conn.private[:authentication_result]
      assert to_string(user.email) == email
      assert user.__metadata__.token
    end

    # Synced passkeys report a constant sign count of 0, so the counter can't
    # tell a second use of a challenge from the first.
    test "rejects a replayed assertion from a synced passkey", %{strategy: strategy} do
      email = "sign-in-replay@example.com"
      passkey = register_passkey(strategy, email)

      challenge_conn = authentication_challenge_conn(strategy, email)
      assertion = sign_assertion(challenge_conn, passkey, sign_count: 0)

      first = sign_in_conn(strategy, challenge_conn, email, passkey, assertion: assertion)
      assert {:ok, _} = first.private[:authentication_result]

      replay = sign_in_conn(strategy, challenge_conn, email, passkey, assertion: assertion)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               replay.private[:authentication_result]
    end
  end

  # The challenge a ceremony is verified against is rebuilt from the session,
  # so these go through the plugs rather than handing `Actions` a
  # hand-built `Wax.Challenge`: a setting the rebuild drops is only visible
  # on this path.
  describe "user_verification" do
    @up 0x01
    @up_uv 0x05
    @up_at 0x41
    @up_uv_at 0x45

    test "\"required\" rejects an assertion without the UV flag", %{strategy: strategy} do
      email = "uv-required-sign-in@example.com"
      passkey = register_passkey(strategy, email)
      strategy = %{strategy | user_verification: "required"}

      challenge_conn = authentication_challenge_conn(strategy, email)
      conn = sign_in_conn(strategy, challenge_conn, email, passkey, sign_count: 1, flags: @up)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               conn.private[:authentication_result]
    end

    test "\"required\" accepts an assertion with the UV flag", %{strategy: strategy} do
      email = "uv-required-sign-in-ok@example.com"
      passkey = register_passkey(strategy, email)
      strategy = %{strategy | user_verification: "required"}

      challenge_conn = authentication_challenge_conn(strategy, email)
      conn = sign_in_conn(strategy, challenge_conn, email, passkey, sign_count: 1, flags: @up_uv)

      assert {:ok, _user} = conn.private[:authentication_result]
    end

    test "\"preferred\" accepts an assertion without the UV flag", %{strategy: strategy} do
      email = "uv-preferred-sign-in@example.com"
      passkey = register_passkey(strategy, email)

      challenge_conn = authentication_challenge_conn(strategy, email)
      conn = sign_in_conn(strategy, challenge_conn, email, passkey, sign_count: 1, flags: @up)

      assert {:ok, _user} = conn.private[:authentication_result]
    end

    test "\"required\" rejects a registration without the UV flag", %{strategy: strategy} do
      strategy = %{strategy | user_verification: "required"}
      email = "uv-required-register@example.com"

      challenge_conn = registration_challenge_conn(strategy, email)
      conn = register_conn(strategy, challenge_conn, email, flags: @up_at)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               conn.private[:authentication_result]
    end

    test "\"required\" accepts a registration with the UV flag", %{strategy: strategy} do
      strategy = %{strategy | user_verification: "required"}
      email = "uv-required-register-ok@example.com"

      challenge_conn = registration_challenge_conn(strategy, email)
      conn = register_conn(strategy, challenge_conn, email, flags: @up_uv_at)

      assert {:ok, _user} = conn.private[:authentication_result]
    end
  end

  describe "timeout" do
    test "a ceremony may run past two minutes when the timeout allows it", %{
      strategy: strategy
    } do
      email = "long-timeout@example.com"
      passkey = register_passkey(strategy, email)
      strategy = %{strategy | timeout: 300_000}

      challenge_conn = authentication_challenge_conn(strategy, email)

      conn =
        sign_in_conn(strategy, challenge_conn, email, passkey, sign_count: 1, challenge_age: 200)

      assert {:ok, _user} = conn.private[:authentication_result]
    end

    test "a ceremony that outlives the timeout is rejected", %{strategy: strategy} do
      email = "short-timeout@example.com"
      passkey = register_passkey(strategy, email)

      challenge_conn = authentication_challenge_conn(strategy, email)

      conn =
        sign_in_conn(strategy, challenge_conn, email, passkey, sign_count: 1, challenge_age: 90)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               conn.private[:authentication_result]
    end
  end

  describe "the sign-in action" do
    test "resolves no user when called outside the ceremony", %{strategy: strategy} do
      email = "sign-in-direct@example.com"
      register_passkey(strategy, email)

      assert {:error, %Ash.Error.Forbidden{}} = Example.sign_in_with_webauthn(email)
    end
  end

  describe "authentication_challenge/2" do
    # The endpoint is public. Listing a submitted identity's credentials would
    # disclose them — and the account's existence — to anyone who asks.
    test "never discloses credentials, even when the identity is known", %{
      strategy: strategy
    } do
      email = "no-allow-credentials@example.com"
      register_passkey(strategy, email)

      known = authentication_challenge_conn(strategy, email)
      unknown = authentication_challenge_conn(strategy, "nobody@example.com")

      assert Jason.decode!(known.resp_body)["allowCredentials"] == []
      assert Jason.decode!(unknown.resp_body)["allowCredentials"] == []

      # Nor does the stored challenge carry them for the server side.
      stored = Plug.Conn.get_session(known, "webauthn_authentication_challenge_webauthn")
      assert stored.allow_credentials == []
    end

    test "a known user still signs in with the discoverable credential", %{
      strategy: strategy
    } do
      email = "discoverable-identity-mode@example.com"
      passkey = register_passkey(strategy, email)

      challenge_conn = authentication_challenge_conn(strategy, email)
      conn = sign_in_conn(strategy, challenge_conn, email, passkey, sign_count: 1)

      assert {:ok, user} = conn.private[:authentication_result]
      assert to_string(user.email) == email
    end

    test "a submitted identity must still match the credential's owner", %{
      strategy: strategy
    } do
      passkey = register_passkey(strategy, "owner@example.com")
      register_passkey(strategy, "someone-else@example.com")

      challenge_conn = authentication_challenge_conn(strategy, "someone-else@example.com")

      conn =
        sign_in_conn(strategy, challenge_conn, "someone-else@example.com", passkey, sign_count: 1)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               conn.private[:authentication_result]
    end
  end

  describe "verify_challenge/2" do
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
        |> conn("/user_with_webauthn/webauthn/verify_challenge", %{})
        |> SessionPipeline.call([])
        |> Ash.PlugHelpers.set_actor(user)
        |> WebAuthn.Plug.verify_challenge(strategy)

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

  describe "hints" do
    # Every challenge endpoint has to carry the hints, since a device with no
    # authenticator of its own needs the cross-device option to enrol a passkey
    # as much as it needs it to use one.
    setup %{strategy: strategy} do
      user =
        Example.UserWithWebAuthn
        |> Ash.Changeset.for_create(:create, %{email: "hints@example.com"})
        |> Ash.create!()

      hinted = %{strategy | hints: [:hybrid, :security_key]}

      challenges = %{
        registration_challenge: fn strategy, params ->
          :get
          |> conn("/user_with_webauthn/webauthn/registration_challenge", params)
          |> SessionPipeline.call([])
          |> WebAuthn.Plug.registration_challenge(strategy)
        end,
        authentication_challenge: fn strategy, params ->
          :get
          |> conn("/user_with_webauthn/webauthn/authentication_challenge", params)
          |> SessionPipeline.call([])
          |> WebAuthn.Plug.authentication_challenge(strategy)
        end,
        add_credential_challenge: fn strategy, params ->
          :get
          |> conn("/user_with_webauthn/webauthn/add_credential_challenge", params)
          |> SessionPipeline.call([])
          |> Ash.PlugHelpers.set_actor(user)
          |> WebAuthn.Plug.add_credential_challenge(strategy)
        end,
        verify_challenge: fn strategy, params ->
          :get
          |> conn("/user_with_webauthn/webauthn/verify_challenge", params)
          |> SessionPipeline.call([])
          |> Ash.PlugHelpers.set_actor(user)
          |> WebAuthn.Plug.verify_challenge(strategy)
        end
      }

      %{hinted: hinted, challenges: challenges}
    end

    test "every challenge endpoint carries the configured hints", %{
      hinted: hinted,
      challenges: challenges
    } do
      for {phase, request} <- challenges do
        body = request.(hinted, %{}) |> Map.fetch!(:resp_body) |> Jason.decode!()
        assert body["hints"] == ["hybrid", "security-key"], "#{phase} dropped the hints"
      end
    end

    test "the member is omitted entirely when no hints are configured", %{
      strategy: strategy,
      challenges: challenges
    } do
      for {phase, request} <- challenges do
        body = request.(strategy, %{}) |> Map.fetch!(:resp_body) |> Jason.decode!()
        refute Map.has_key?(body, "hints"), "#{phase} sent an empty hints member"
      end
    end

    test "a request param overrides the configuration when permitted", %{
      hinted: hinted,
      challenges: challenges
    } do
      overridable = %{hinted | allow_hint_override?: true}

      for {phase, request} <- challenges do
        body =
          request.(overridable, %{"hints" => "hybrid"})
          |> Map.fetch!(:resp_body)
          |> Jason.decode!()

        assert body["hints"] == ["hybrid"], "#{phase} ignored the requested hints"
      end
    end

    test "a request param is ignored unless allow_hint_override? is set", %{
      hinted: hinted,
      challenges: challenges
    } do
      for {phase, request} <- challenges do
        body =
          request.(hinted, %{"hints" => "client-device"})
          |> Map.fetch!(:resp_body)
          |> Jason.decode!()

        assert body["hints"] == ["hybrid", "security-key"],
               "#{phase} honoured an unpermitted hint"
      end
    end

    test "requested hints are accepted as a list and normalised", %{
      hinted: hinted,
      challenges: %{authentication_challenge: request}
    } do
      overridable = %{hinted | allow_hint_override?: true}

      body =
        request.(overridable, %{"hints" => [" Hybrid ", "SECURITY-KEY", "hybrid"]})
        |> Map.fetch!(:resp_body)
        |> Jason.decode!()

      assert body["hints"] == ["hybrid", "security-key"]
    end

    test "unrecognised requested hints are discarded", %{
      hinted: hinted,
      challenges: %{authentication_challenge: request}
    } do
      overridable = %{hinted | allow_hint_override?: true}

      body =
        request.(overridable, %{"hints" => "drop-tables,hybrid"})
        |> Map.fetch!(:resp_body)
        |> Jason.decode!()

      assert body["hints"] == ["hybrid"]
    end

    test "a request naming no valid hint falls back to the configuration", %{
      hinted: hinted,
      challenges: %{authentication_challenge: request}
    } do
      overridable = %{hinted | allow_hint_override?: true}

      for params <- [
            %{"hints" => "nonsense"},
            %{"hints" => ""},
            %{"hints" => List.duplicate("nope", 50)},
            %{"hints" => %{"not" => "a list"}}
          ] do
        body = request.(overridable, params) |> Map.fetch!(:resp_body) |> Jason.decode!()
        assert body["hints"] == ["hybrid", "security-key"], "#{inspect(params)} was not rejected"
      end
    end

    test "hints do not leak into the stored challenge, so assertions still verify", %{
      strategy: strategy
    } do
      overridable = %{strategy | hints: [:hybrid], allow_hint_override?: true}

      hinted_conn = registration_challenge_conn(overridable, "hints-roundtrip@example.com")
      assert Jason.decode!(hinted_conn.resp_body)["hints"] == ["hybrid"]

      conn = register_conn(overridable, hinted_conn, "hints-roundtrip@example.com")

      assert {:ok, user} = conn.private[:authentication_result]
      assert user.email |> to_string() == "hints-roundtrip@example.com"
    end
  end

  describe "authenticatorSelection" do
    test "omits authenticatorAttachment when there is no preference", %{strategy: strategy} do
      # `null` is not a member of the AuthenticatorAttachment enum -- absence is
      # how "any authenticator" is spelled.
      body =
        strategy
        |> registration_challenge_conn("attachment@example.com")
        |> Map.fetch!(:resp_body)
        |> Jason.decode!()

      refute Map.has_key?(body["authenticatorSelection"], "authenticatorAttachment")
      assert body["authenticatorSelection"]["residentKey"] == "required"
      assert body["authenticatorSelection"]["requireResidentKey"] == true
    end

    test "sends authenticatorAttachment when configured", %{strategy: strategy} do
      body =
        %{strategy | authenticator_attachment: :cross_platform}
        |> registration_challenge_conn("attachment2@example.com")
        |> Map.fetch!(:resp_body)
        |> Jason.decode!()

      # Hyphenated, per the AuthenticatorAttachment enum -- a client which does
      # not recognise the value ignores the member outright.
      assert body["authenticatorSelection"]["authenticatorAttachment"] == "cross-platform"
    end
  end

  @attestation_session_key "webauthn_attestation_challenge_webauthn"
  @authentication_session_key "webauthn_authentication_challenge_webauthn"

  defp registration_challenge_conn(strategy, email) do
    :get
    |> conn("/user_with_web_authn/webauthn/registration_challenge", %{"email" => email})
    |> SessionPipeline.call([])
    |> WebAuthn.Plug.registration_challenge(strategy)
  end

  # The origin the browser signs. `Example.UserWithWebAuthn` configures
  # `origin "https://example.com"`, an exact allowlist; the request's own
  # host (Plug.Test's www.example.com) plays no part.
  @origin "https://example.com"

  # Build a register POST that answers the server-issued challenge. The test
  # SessionPipeline mints a fresh secret_key_base per conn, so cookies can't
  # round-trip; the session entry is transplanted instead.
  defp register_conn(strategy, challenge_conn, email, fixture_opts \\ []) do
    body = Jason.decode!(challenge_conn.resp_body)
    challenge_bytes = Base.url_decode64!(body["challenge"], padding: false)
    session_data = Plug.Conn.get_session(challenge_conn, @attestation_session_key)

    fixture =
      WebAuthnFixtures.generate_registration(
        Keyword.merge(fixture_opts,
          origin: @origin,
          rp_id: "example.com",
          challenge_bytes: challenge_bytes
        )
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

  # Registers `email` through the registration ceremony, and returns the
  # registration fixture so tests can sign assertions with it.
  defp register_passkey(strategy, email) do
    challenge_conn = registration_challenge_conn(strategy, email)

    passkey =
      WebAuthnFixtures.generate_registration(
        origin: @origin,
        rp_id: "example.com",
        challenge_bytes: challenge_bytes(challenge_conn)
      )

    conn =
      :post
      |> conn("/user_with_web_authn/webauthn/register", %{
        "user_with_web_authn" => %{
          "email" => email,
          "attestation_object" => passkey.attestation_object,
          "client_data_json" => passkey.client_data_json,
          "raw_id" => passkey.raw_id
        }
      })
      |> SessionPipeline.call([])
      |> Plug.Conn.put_session(
        @attestation_session_key,
        Plug.Conn.get_session(challenge_conn, @attestation_session_key)
      )
      |> WebAuthn.Plug.register(strategy)

    assert {:ok, _user} = conn.private[:authentication_result]
    passkey
  end

  defp authentication_challenge_conn(strategy, email) do
    :get
    |> conn("/user_with_web_authn/webauthn/authentication_challenge", %{"email" => email})
    |> SessionPipeline.call([])
    |> WebAuthn.Plug.authentication_challenge(strategy)
  end

  defp sign_assertion(challenge_conn, passkey, opts) do
    WebAuthnFixtures.generate_authentication(
      passkey,
      Keyword.merge(opts,
        challenge_bytes: challenge_bytes(challenge_conn),
        origin: @origin
      )
    )
  end

  # Answers the challenge issued by `challenge_conn`, transplanting its
  # session entry as `register_conn/3` does.
  #
  # `challenge_age: seconds` backdates the stored challenge's issue time, as
  # if the user had spent that long in the browser's dialog. Only the
  # server-side challenge ages; its token keeps its real expiry.
  defp sign_in_conn(strategy, challenge_conn, email, passkey, opts) do
    assertion =
      Keyword.get_lazy(opts, :assertion, fn ->
        sign_assertion(challenge_conn, passkey, Keyword.take(opts, [:sign_count, :flags]))
      end)

    session_data =
      challenge_conn
      |> Plug.Conn.get_session(@authentication_session_key)
      |> Map.update!(:issued_at, &(&1 - Keyword.get(opts, :challenge_age, 0)))

    :post
    |> conn("/user_with_web_authn/webauthn/sign_in", %{
      "user_with_web_authn" => %{
        "email" => email,
        "raw_id" => Base.url_encode64(assertion.raw_id, padding: false),
        "authenticator_data" => assertion.authenticator_data,
        "signature" => assertion.signature,
        "client_data_json" => assertion.client_data_json
      }
    })
    |> SessionPipeline.call([])
    |> Plug.Conn.put_session(@authentication_session_key, session_data)
    |> WebAuthn.Plug.sign_in(strategy)
  end

  defp challenge_bytes(challenge_conn) do
    challenge_conn.resp_body
    |> Jason.decode!()
    |> Map.fetch!("challenge")
    |> Base.url_decode64!(padding: false)
  end
end
