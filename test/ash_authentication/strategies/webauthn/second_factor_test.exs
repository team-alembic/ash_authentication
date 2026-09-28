# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.SecondFactorTest do
  @moduledoc """
  WebAuthn as a second factor, end to end over the Plug endpoints: a user
  signs in with a password, enrols a passkey, then proves possession of it
  through `verify_challenge` and `verify`.

  Runs against `Example.UserWithWebAuthnSecondFactor`, which is configured the
  way `--mode 2fa` generates it — no WebAuthn registration or sign-in.
  """
  use DataCase, async: false

  import Plug.Test

  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Info
  alias AshAuthentication.Jwt
  alias AshAuthentication.Strategy
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

  @resource Example.UserWithWebAuthnSecondFactor
  @password "correct horse battery staple"
  # `Plug.Test` requests arrive on http://www.example.com, which is the
  # origin the challenge endpoints record.
  @origin "http://www.example.com"
  @rp_id "example.com"
  @attestation_key "webauthn_attestation_challenge_webauthn"
  @authentication_key "webauthn_authentication_challenge_webauthn"

  setup do
    %{strategy: Info.strategy!(@resource, :webauthn)}
  end

  describe "configuration" do
    test "exposes only the verify and add-credential ceremonies", %{strategy: strategy} do
      assert Strategy.phases(strategy) == [
               :verify_challenge,
               :verify,
               :add_credential_challenge,
               :add_credential
             ]

      paths = strategy |> Strategy.routes() |> Enum.map(&elem(&1, 0))

      for phase <- ~w[registration_challenge register authentication_challenge sign_in] do
        refute Enum.any?(paths, &String.ends_with?(&1, "/" <> phase)),
               "a 2fa-only strategy must not route `#{phase}`"
      end
    end

    test "builds the verify action but no WebAuthn sign-in or registration actions" do
      assert Ash.Resource.Info.action(@resource, :verify_webauthn)
      refute Ash.Resource.Info.action(@resource, :sign_in_with_webauthn)
      refute Ash.Resource.Info.action(@resource, :sign_in_with_webauthn_token)
      refute Ash.Resource.Info.action(@resource, :register_with_webauthn)
    end
  end

  describe "verify_challenge/2" do
    test "fails without an authenticated actor", %{strategy: strategy} do
      conn = verify_challenge_conn(strategy, nil)

      assert {:error, %AuthenticationFailed{}} = conn.private[:authentication_result]
      refute Plug.Conn.get_session(conn, @authentication_key)
    end

    test "offers only the actor's own credentials", %{strategy: strategy} do
      user = sign_in_with_password("offers@example.com")
      passkey = enrol_passkey(strategy, user)

      other_user = sign_in_with_password("offers-other@example.com")
      enrol_passkey(strategy, other_user)

      conn = verify_challenge_conn(strategy, user)

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert is_binary(body["challenge"])
      assert body["rpId"] == @rp_id

      assert [%{"id" => id, "type" => "public-key"}] = body["allowCredentials"]
      assert Base.url_decode64!(id, padding: false) == passkey.credential_id

      assert %{} = Plug.Conn.get_session(conn, @authentication_key)
    end
  end

  describe "verify/2" do
    test "a password-authenticated user proves possession of their passkey", %{
      strategy: strategy
    } do
      user = sign_in_with_password("verify@example.com")
      passkey = enrol_passkey(strategy, user)

      challenge_conn = verify_challenge_conn(strategy, user)
      conn = verify_conn(strategy, user, challenge_conn, passkey)

      assert {:ok, verified} = conn.private[:authentication_result]
      assert verified.id == user.id
      assert %DateTime{} = verified_at = verified.__metadata__.webauthn_verified_at

      # The fresh token carries the second-factor claim for API clients, and
      # still identifies the same user.
      {:ok, claims} = Jwt.peek(verified.__metadata__.token)
      assert claims["sub"] == AshAuthentication.user_to_subject(user)
      assert {:ok, ^verified_at, _} = DateTime.from_iso8601(claims["webauthn_verified_at"])

      # The challenge is single-use.
      refute Plug.Conn.get_session(conn, @authentication_key)
    end

    test "fails without an authenticated actor, even with a pending challenge", %{
      strategy: strategy
    } do
      user = sign_in_with_password("verify-anon@example.com")
      passkey = enrol_passkey(strategy, user)

      challenge_conn = verify_challenge_conn(strategy, user)
      conn = verify_conn(strategy, nil, challenge_conn, passkey)

      assert {:error, %AuthenticationFailed{}} = conn.private[:authentication_result]
    end

    test "fails without a pending challenge", %{strategy: strategy} do
      user = sign_in_with_password("verify-no-challenge@example.com")
      passkey = enrol_passkey(strategy, user)
      assertion = WebAuthnFixtures.generate_authentication(passkey)

      conn =
        :post
        |> conn(path(strategy, :verify), %{subject_name() => assertion_params(assertion)})
        |> SessionPipeline.call([])
        |> Ash.PlugHelpers.set_actor(user)
        |> WebAuthn.Plug.verify(strategy)

      assert {:error, %AuthenticationFailed{}} = conn.private[:authentication_result]
    end

    test "rejects another user's passkey", %{strategy: strategy} do
      user = sign_in_with_password("verify-victim@example.com")
      enrol_passkey(strategy, user)

      attacker = sign_in_with_password("verify-attacker@example.com")
      attacker_passkey = enrol_passkey(strategy, attacker)

      # The attacker signs a challenge issued to the victim's session.
      challenge_conn = verify_challenge_conn(strategy, user)
      conn = verify_conn(strategy, user, challenge_conn, attacker_passkey)

      assert {:error, %AuthenticationFailed{}} = conn.private[:authentication_result]
    end

    test "rejects an assertion signed over a different challenge", %{strategy: strategy} do
      user = sign_in_with_password("verify-stale@example.com")
      passkey = enrol_passkey(strategy, user)

      challenge_conn = verify_challenge_conn(strategy, user)
      assertion = WebAuthnFixtures.generate_authentication(passkey)

      conn =
        :post
        |> conn(path(strategy, :verify), %{subject_name() => assertion_params(assertion)})
        |> SessionPipeline.call([])
        |> Plug.Conn.put_session(
          @authentication_key,
          Plug.Conn.get_session(challenge_conn, @authentication_key)
        )
        |> Ash.PlugHelpers.set_actor(user)
        |> WebAuthn.Plug.verify(strategy)

      assert {:error, %AuthenticationFailed{}} = conn.private[:authentication_result]
    end

    test "rejects a replayed assertion from an authenticator with a counter", %{
      strategy: strategy
    } do
      user = sign_in_with_password("verify-replay@example.com")
      passkey = enrol_passkey(strategy, user)

      challenge_conn = verify_challenge_conn(strategy, user)

      assertion =
        passkey
        |> WebAuthnFixtures.generate_authentication(
          challenge_bytes: challenge_bytes(challenge_conn),
          origin: @origin,
          sign_count: 1
        )

      first = verify_conn(strategy, user, challenge_conn, passkey, assertion)
      assert {:ok, _} = first.private[:authentication_result]

      # A client holding on to the pre-verify session cookie still has the
      # challenge; the stored sign count is what refuses the second use.
      replay = verify_conn(strategy, user, challenge_conn, passkey, assertion)
      assert {:error, %AuthenticationFailed{}} = replay.private[:authentication_result]
    end

    # Synced passkeys report a constant sign count of 0, so the counter can't
    # tell a second use of a challenge from the first.
    test "rejects a replayed assertion from a synced passkey", %{strategy: strategy} do
      user = sign_in_with_password("verify-replay-synced@example.com")
      passkey = enrol_passkey(strategy, user)

      challenge_conn = verify_challenge_conn(strategy, user)

      assertion =
        WebAuthnFixtures.generate_authentication(passkey,
          challenge_bytes: challenge_bytes(challenge_conn),
          origin: @origin,
          sign_count: 0
        )

      first = verify_conn(strategy, user, challenge_conn, passkey, assertion)
      assert {:ok, _} = first.private[:authentication_result]

      replay = verify_conn(strategy, user, challenge_conn, passkey, assertion)
      assert {:error, %AuthenticationFailed{}} = replay.private[:authentication_result]
    end
  end

  describe "the verify action" do
    test "resolves no user when called outside the ceremony", %{strategy: strategy} do
      user = sign_in_with_password("verify-direct@example.com")
      passkey = enrol_passkey(strategy, user)
      params = passkey |> WebAuthnFixtures.generate_authentication() |> assertion_params()

      assert {:error, %Ash.Error.Forbidden{}} =
               Example.verify_webauthn(
                 params["raw_id"],
                 params["authenticator_data"],
                 params["signature"],
                 params["client_data_json"],
                 actor: user
               )
    end
  end

  defp sign_in_with_password(email) do
    strategy = Info.strategy!(@resource, :password)
    params = %{"email" => email, "password" => @password}

    {:ok, _user} =
      Strategy.action(
        strategy,
        :register,
        Map.put(params, "password_confirmation", @password),
        []
      )

    {:ok, user} = Strategy.action(strategy, :sign_in, params, [])
    user
  end

  # Enrols a passkey for `user` through the add-credential ceremony, and
  # returns the registration fixture so tests can sign assertions with it.
  defp enrol_passkey(strategy, user) do
    challenge_conn =
      :get
      |> conn(path(strategy, :add_credential_challenge), %{})
      |> SessionPipeline.call([])
      |> Ash.PlugHelpers.set_actor(user)
      |> WebAuthn.Plug.add_credential_challenge(strategy)

    passkey =
      WebAuthnFixtures.generate_registration(
        origin: @origin,
        rp_id: @rp_id,
        challenge_bytes: challenge_bytes(challenge_conn)
      )

    conn =
      :post
      |> conn(path(strategy, :add_credential), %{
        subject_name() => %{
          "attestation_object" => passkey.attestation_object,
          "client_data_json" => passkey.client_data_json,
          "raw_id" => passkey.raw_id
        }
      })
      |> SessionPipeline.call([])
      |> Plug.Conn.put_session(
        @attestation_key,
        Plug.Conn.get_session(challenge_conn, @attestation_key)
      )
      |> Ash.PlugHelpers.set_actor(user)
      |> WebAuthn.Plug.add_credential(strategy)

    assert {:ok, _} = conn.private[:authentication_result]
    passkey
  end

  defp verify_challenge_conn(strategy, actor) do
    :get
    |> conn(path(strategy, :verify_challenge), %{})
    |> SessionPipeline.call([])
    |> maybe_set_actor(actor)
    |> WebAuthn.Plug.verify_challenge(strategy)
  end

  # Answers the challenge issued by `challenge_conn`. The test
  # SessionPipeline mints a fresh secret per conn, so cookies can't
  # round-trip; the session entry is transplanted instead.
  defp verify_conn(strategy, actor, challenge_conn, passkey, assertion \\ nil) do
    assertion =
      assertion ||
        WebAuthnFixtures.generate_authentication(passkey,
          challenge_bytes: challenge_bytes(challenge_conn),
          origin: @origin
        )

    :post
    |> conn(path(strategy, :verify), %{subject_name() => assertion_params(assertion)})
    |> SessionPipeline.call([])
    |> Plug.Conn.put_session(
      @authentication_key,
      Plug.Conn.get_session(challenge_conn, @authentication_key)
    )
    |> maybe_set_actor(actor)
    |> WebAuthn.Plug.verify(strategy)
  end

  defp assertion_params(assertion) do
    %{
      "raw_id" => Base.url_encode64(assertion.raw_id, padding: false),
      "authenticator_data" => assertion.authenticator_data,
      "signature" => assertion.signature,
      "client_data_json" => assertion.client_data_json
    }
  end

  defp challenge_bytes(challenge_conn) do
    challenge_conn.resp_body
    |> Jason.decode!()
    |> Map.fetch!("challenge")
    |> Base.url_decode64!(padding: false)
  end

  defp maybe_set_actor(conn, nil), do: conn
  defp maybe_set_actor(conn, actor), do: Ash.PlugHelpers.set_actor(conn, actor)

  defp path(strategy, phase) do
    {path, ^phase} =
      strategy
      |> Strategy.routes()
      |> Enum.find(&(elem(&1, 1) == phase))

    path
  end

  defp subject_name, do: @resource |> Info.authentication_subject_name!() |> to_string()
end
