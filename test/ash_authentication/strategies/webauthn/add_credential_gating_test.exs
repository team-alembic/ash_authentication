# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.AddCredentialGatingTest do
  @moduledoc """
  `add_credential_enabled?` and `add_credential_max_authentication_age`:
  who may add a passkey to an existing account, and when.

  Runs against `Example.UserWithWebAuthnSecondFactor`, where users sign in
  with a password and then enrol passkeys — the flow these options guard.
  """
  use DataCase, async: false

  import Plug.Test

  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.{Info, Strategy}
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.{Actions, RecentAuthentication}
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

  @resource Example.UserWithWebAuthnSecondFactor
  @password "correct horse battery staple"
  @origin "http://www.example.com"
  @rp_id "example.com"
  @attestation_key "webauthn_attestation_challenge_webauthn"

  setup do
    %{strategy: Info.strategy!(@resource, :webauthn)}
  end

  describe "add_credential_enabled?" do
    test "is on by default", %{strategy: strategy} do
      assert strategy.add_credential_enabled?
      assert :add_credential_challenge in Strategy.phases(strategy)
      assert :add_credential in Strategy.actions(strategy)
    end

    test "false removes the phases and the action", %{strategy: strategy} do
      strategy = %{strategy | add_credential_enabled?: false}

      refute :add_credential_challenge in Strategy.phases(strategy)
      refute :add_credential in Strategy.phases(strategy)
      refute :add_credential in Strategy.actions(strategy)
    end

    test "false refuses the plugs and the action, even for a fresh sign-in", %{
      strategy: strategy
    } do
      strategy = %{strategy | add_credential_enabled?: false}
      user = sign_in_with_password("disabled@example.com")

      challenge_conn = add_credential_challenge_conn(strategy, user)
      assert {:error, %AuthenticationFailed{}} = challenge_conn.private[:authentication_result]
      refute Plug.Conn.get_session(challenge_conn, @attestation_key)

      passkey = WebAuthnFixtures.generate_registration(origin: @origin, rp_id: @rp_id)

      assert {:error, %AuthenticationFailed{}} =
               Actions.add_credential(strategy, registration_params(passkey),
                 challenge: attestation_challenge(passkey),
                 user: user
               )

      assert {:ok, []} = Actions.list_credentials(strategy, user, [])
    end
  end

  describe "add_credential_max_authentication_age" do
    test "is unset by default: any authenticated user may add a passkey", %{
      strategy: strategy
    } do
      assert strategy.add_credential_max_authentication_age == nil

      user = "no-window@example.com" |> sign_in_with_password() |> strip_metadata()
      assert {:ok, _} = enrol(strategy, user).private[:authentication_result]
    end

    test "a fresh sign-in is recent enough", %{strategy: strategy} do
      strategy = %{strategy | add_credential_max_authentication_age: {5, :minutes}}
      user = sign_in_with_password("fresh@example.com")

      assert {:ok, _} = enrol(strategy, user).private[:authentication_result]
    end

    test "a sign-in older than the window is refused before any challenge is issued", %{
      strategy: strategy
    } do
      strategy = %{strategy | add_credential_max_authentication_age: {5, :minutes}}

      user =
        "stale-token@example.com"
        |> sign_in_with_password()
        |> Ash.Resource.put_metadata(:token, unsigned_token(age: 3600))

      challenge_conn = add_credential_challenge_conn(strategy, user)

      assert {:error, %AuthenticationFailed{} = error} =
               challenge_conn.private[:authentication_result]

      assert error.caused_by.message =~ "recent authentication"
      refute Plug.Conn.get_session(challenge_conn, @attestation_key)
    end

    test "a recent second-factor verification counts, however old the sign-in", %{
      strategy: strategy
    } do
      strategy = %{strategy | add_credential_max_authentication_age: 300}

      user =
        "stepped-up@example.com"
        |> sign_in_with_password()
        |> strip_metadata()
        |> Ash.Resource.put_metadata(:webauthn_verified_at, DateTime.utc_now())

      assert {:ok, _} = enrol(strategy, user).private[:authentication_result]
    end

    test "a stale second-factor verification does not", %{strategy: strategy} do
      strategy = %{strategy | add_credential_max_authentication_age: 300}

      user =
        "stale-step-up@example.com"
        |> sign_in_with_password()
        |> strip_metadata()
        |> Ash.Resource.put_metadata(
          :totp_verified_at,
          DateTime.add(DateTime.utc_now(), -3600, :second)
        )

      assert {:error, %AuthenticationFailed{}} =
               add_credential_challenge_conn(strategy, user).private[:authentication_result]
    end

    test "an actor with no evidence of when they authenticated is refused", %{
      strategy: strategy
    } do
      strategy = %{strategy | add_credential_max_authentication_age: {1, :days}}
      user = "no-evidence@example.com" |> sign_in_with_password() |> strip_metadata()

      assert {:error, %AuthenticationFailed{}} =
               add_credential_challenge_conn(strategy, user).private[:authentication_result]
    end

    test "the bearer token a request presents counts for that actor", %{strategy: strategy} do
      strategy = %{strategy | add_credential_max_authentication_age: {5, :minutes}}
      signed_in = sign_in_with_password("bearer@example.com")
      user = strip_metadata(signed_in)

      conn =
        enrol(strategy, user, fn conn ->
          Plug.Conn.put_req_header(
            conn,
            "authorization",
            "Bearer " <> signed_in.__metadata__.token
          )
        end)

      assert {:ok, _} = conn.private[:authentication_result]
    end

    test "a bearer token issued to someone else does not", %{strategy: strategy} do
      strategy = %{strategy | add_credential_max_authentication_age: {5, :minutes}}
      someone_else = sign_in_with_password("bearer-other@example.com")
      user = "bearer-victim@example.com" |> sign_in_with_password() |> strip_metadata()

      challenge_conn =
        add_credential_challenge_conn(strategy, user, fn conn ->
          Plug.Conn.put_req_header(
            conn,
            "authorization",
            "Bearer " <> someone_else.__metadata__.token
          )
        end)

      assert {:error, %AuthenticationFailed{}} = challenge_conn.private[:authentication_result]
    end

    test "the action enforces it too, with an explicit authenticated_at", %{strategy: strategy} do
      strategy = %{strategy | add_credential_max_authentication_age: {5, :minutes}}
      user = "action@example.com" |> sign_in_with_password() |> strip_metadata()
      passkey = WebAuthnFixtures.generate_registration(origin: @origin, rp_id: @rp_id)

      assert {:error, %AuthenticationFailed{}} =
               Actions.add_credential(strategy, registration_params(passkey),
                 challenge: attestation_challenge(passkey),
                 user: user,
                 authenticated_at: DateTime.add(DateTime.utc_now(), -3600, :second)
               )

      assert {:ok, _credential} =
               Actions.add_credential(strategy, registration_params(passkey),
                 challenge: attestation_challenge(passkey),
                 user: user,
                 authenticated_at: DateTime.utc_now()
               )
    end
  end

  describe "RecentAuthentication.authenticated_at/2" do
    test "takes the most recent of every source" do
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      hour_ago = DateTime.add(now, -3600, :second)

      user =
        %Example.UserWithWebAuthnSecondFactor{}
        |> Ash.Resource.put_metadata(:token, unsigned_token(age: 7200))
        |> Ash.Resource.put_metadata(:totp_verified_at, DateTime.to_iso8601(hour_ago))
        |> Ash.Resource.put_metadata(:webauthn_verified_at, now)

      assert RecentAuthentication.authenticated_at(user) == now

      assert RecentAuthentication.authenticated_at(user,
               authenticated_at: DateTime.add(now, 60, :second)
             ) == DateTime.add(now, 60, :second)
    end

    test "is nil without any evidence, or with an unreadable token" do
      assert RecentAuthentication.authenticated_at(%Example.UserWithWebAuthnSecondFactor{}) ==
               nil

      user =
        Ash.Resource.put_metadata(%Example.UserWithWebAuthnSecondFactor{}, :token, "not-a-jwt")

      assert RecentAuthentication.authenticated_at(user) == nil
    end
  end

  # Signs a password user up and in; the returned user carries the session
  # token (`__metadata__.token`) the way a session-loaded actor does.
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

  # The same user, as an actor that brings no evidence of when it signed in.
  defp strip_metadata(user), do: %{user | __metadata__: %{}}

  # A JWT-shaped token issued `age` seconds ago. `RecentAuthentication` only
  # peeks at its claims, so it needn't be signed.
  defp unsigned_token(opts) do
    claims = %{"iat" => System.system_time(:second) - Keyword.fetch!(opts, :age)}
    segment = &Base.url_encode64(Jason.encode!(&1), padding: false)
    "#{segment.(%{"alg" => "HS256", "typ" => "JWT"})}.#{segment.(claims)}.signature"
  end

  defp add_credential_challenge_conn(strategy, user, prepare \\ & &1) do
    :get
    |> conn(path(strategy, :add_credential_challenge), %{})
    |> SessionPipeline.call([])
    |> prepare.()
    |> Ash.PlugHelpers.set_actor(user)
    |> WebAuthn.Plug.add_credential_challenge(strategy)
  end

  # Runs both add-credential phases for `user` and returns the final conn.
  defp enrol(strategy, user, prepare \\ & &1) do
    challenge_conn = add_credential_challenge_conn(strategy, user, prepare)
    assert challenge_conn.status == 200

    passkey =
      WebAuthnFixtures.generate_registration(
        origin: @origin,
        rp_id: @rp_id,
        challenge_bytes: challenge_bytes(challenge_conn)
      )

    :post
    |> conn(path(strategy, :add_credential), %{subject_name() => registration_params(passkey)})
    |> SessionPipeline.call([])
    |> prepare.()
    |> Plug.Conn.put_session(
      @attestation_key,
      Plug.Conn.get_session(challenge_conn, @attestation_key)
    )
    |> Ash.PlugHelpers.set_actor(user)
    |> WebAuthn.Plug.add_credential(strategy)
  end

  defp registration_params(passkey) do
    %{
      "attestation_object" => passkey.attestation_object,
      "client_data_json" => passkey.client_data_json,
      "raw_id" => passkey.raw_id
    }
  end

  defp attestation_challenge(passkey) do
    %Wax.Challenge{
      type: :attestation,
      bytes: passkey.challenge_bytes,
      origin: @origin,
      rp_id: @rp_id,
      attestation: "none",
      trusted_attestation_types: [:none, :basic, :self, :uncertain],
      verify_trust_root: false,
      origin_verify_fun: {Wax, :origins_match?, []},
      issued_at: System.system_time(:second)
    }
  end

  defp challenge_bytes(challenge_conn) do
    challenge_conn.resp_body
    |> Jason.decode!()
    |> Map.fetch!("challenge")
    |> Base.url_decode64!(padding: false)
  end

  # Paths come from the strategy as configured, since a test may have turned
  # the phase off on its own copy.
  defp path(_strategy, phase) do
    {path, ^phase} =
      @resource
      |> Info.strategy!(:webauthn)
      |> Strategy.routes()
      |> Enum.find(&(elem(&1, 1) == phase))

    path
  end

  defp subject_name, do: @resource |> Info.authentication_subject_name!() |> to_string()
end
