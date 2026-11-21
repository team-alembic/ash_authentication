# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.MockAdapterCeremoniesTest do
  @moduledoc """
  Every WebAuthn ceremony, end to end, on an adapter that has nothing to do
  with Wax: `AshAuthentication.Test.WebAuthnMockAdapter`.

  If any code path in the strategy, its plugs or its actions still depends
  on Wax — a struct it pattern-matches, an option only Wax understands, a
  function it calls — a ceremony here fails. The strategy under test is
  `Example.UserWithWebAuthn` (configured with `origin "https://example.com"`
  and `rp_id "example.com"`) with its adapter swapped.
  """
  use DataCase, async: false

  import Plug.Test

  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.{Info, Jwt}
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnMockAdapter, as: Mock

  @moduletag feature: :webauthn

  @subject "user_with_web_authn"
  @attestation_key "webauthn_attestation_challenge_webauthn"
  @authentication_key "webauthn_authentication_challenge_webauthn"

  setup do
    strategy = %{Info.strategy!(Example.UserWithWebAuthn, :webauthn) | adapter: Mock}
    %{strategy: strategy}
  end

  describe "through the plugs" do
    test "the registration challenge advertises the adapter's algorithms", %{strategy: strategy} do
      body =
        strategy |> challenge(:registration_challenge, %{"email" => "algs@example.com"}) |> body()

      assert body["pubKeyCredParams"] == [%{"type" => "public-key", "alg" => 5}]
      assert body["rp"]["id"] == "example.com"
      assert is_binary(body["challenge"])
    end

    test "register, sign in, then exchange the sign-in token", %{strategy: strategy} do
      email = "plug-round-trip@example.com"
      {user, credential} = register(strategy, email)
      assert to_string(user.email) == email

      # The stored public key is the mock's COSE symmetric key, through the
      # CoseKey type and back
      {:ok, [stored]} = Actions.list_credentials(strategy, user, [])
      assert stored.credential_id == credential.credential_id
      assert stored.public_key == Mock.public_key(credential)
      assert stored.sign_count == 0

      assert {:ok, signed_in} = sign_in(strategy, credential, email)
      assert signed_in.id == user.id
      assert token = signed_in.__metadata__.token

      exchanged =
        :post
        |> conn("/#{@subject}/webauthn/sign_in_with_token", %{"token" => token})
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.sign_in_with_token(strategy)

      assert {:ok, session_user} = exchanged.private[:authentication_result]
      assert session_user.id == user.id
      assert session_user.__metadata__.token != token
    end

    test "verify_challenge lists the actor's credentials and verify proves possession", %{
      strategy: strategy
    } do
      {user, credential} = register(strategy, "verify@example.com")
      {_other, _} = register(strategy, "verify-other@example.com")

      challenge_conn = challenge(strategy, :verify_challenge, %{}, actor: user)
      body = body(challenge_conn)

      assert [%{"id" => id, "type" => "public-key"}] = body["allowCredentials"]
      assert Base.url_decode64!(id, padding: false) == credential.credential_id

      conn =
        answer(
          strategy,
          :verify,
          challenge_conn,
          @authentication_key,
          assertion(credential, challenge_conn),
          actor: user
        )

      assert {:ok, verified} = conn.private[:authentication_result]
      assert verified.id == user.id
      assert %DateTime{} = verified_at = verified.__metadata__.webauthn_verified_at
      {:ok, claims} = Jwt.peek(verified.__metadata__.token)
      assert {:ok, ^verified_at, _} = DateTime.from_iso8601(claims["webauthn_verified_at"])
    end

    test "verify refuses another user's credential", %{strategy: strategy} do
      {user, _} = register(strategy, "verify-owner@example.com")
      {_attacker, attacker_credential} = register(strategy, "verify-attacker@example.com")

      challenge_conn = challenge(strategy, :verify_challenge, %{}, actor: user)

      conn =
        answer(
          strategy,
          :verify,
          challenge_conn,
          @authentication_key,
          assertion(attacker_credential, challenge_conn),
          actor: user
        )

      assert {:error, %AuthenticationFailed{}} = conn.private[:authentication_result]
    end

    test "add_credential_challenge excludes existing passkeys and add_credential attaches one", %{
      strategy: strategy
    } do
      {user, first} = register(strategy, "add@example.com")

      challenge_conn = challenge(strategy, :add_credential_challenge, %{}, actor: user)
      body = body(challenge_conn)

      assert [%{"id" => excluded}] = body["excludeCredentials"]
      assert Base.url_decode64!(excluded, padding: false) == first.credential_id
      assert body["pubKeyCredParams"] == [%{"type" => "public-key", "alg" => 5}]

      second = Mock.new_credential()

      conn =
        answer(
          strategy,
          :add_credential,
          challenge_conn,
          @attestation_key,
          Mock.attestation(second, challenge_bytes(challenge_conn))
          |> Map.put("label", "Backup key"),
          actor: user
        )

      assert {:ok, added} = conn.private[:authentication_result]
      assert added.credential_id == second.credential_id
      assert added.label == "Backup key"
      assert added.user_handle == Base.url_decode64!(body["user"]["id"], padding: false)

      {:ok, credentials} = Actions.list_credentials(strategy, user, [])
      assert length(credentials) == 2

      # ...and the new passkey signs in
      assert {:ok, _} = sign_in(strategy, second, "add@example.com")
    end

    test "a challenge can be answered once", %{strategy: strategy} do
      email = "single-use@example.com"
      {_user, credential} = register(strategy, email)

      challenge_conn = challenge(strategy, :authentication_challenge, %{"email" => email})
      response = assertion(credential, challenge_conn, sign_count: 0)

      first =
        answer(
          strategy,
          :sign_in,
          challenge_conn,
          @authentication_key,
          Map.put(response, "email", email)
        )

      assert {:ok, _} = first.private[:authentication_result]

      replay =
        answer(
          strategy,
          :sign_in,
          challenge_conn,
          @authentication_key,
          Map.put(response, "email", email)
        )

      assert {:error, %AuthenticationFailed{}} = replay.private[:authentication_result]
    end

    test "a registration challenge cannot answer a sign-in", %{strategy: strategy} do
      email = "cross-type@example.com"
      {_user, credential} = register(strategy, email)

      reg_conn = challenge(strategy, :registration_challenge, %{"email" => email})
      response = assertion(credential, reg_conn)

      conn =
        :post
        |> conn("/#{@subject}/webauthn/sign_in", %{@subject => Map.put(response, "email", email)})
        |> SessionPipeline.call([])
        |> Plug.Conn.put_session(
          @authentication_key,
          Plug.Conn.get_session(reg_conn, @attestation_key)
        )
        |> WebAuthn.Plug.sign_in(strategy)

      assert {:error, %AuthenticationFailed{}} = conn.private[:authentication_result]
    end

    test "the user handle minted at registration must match on sign-in", %{strategy: strategy} do
      email = "handle@example.com"
      {user, credential} = register(strategy, email)
      {:ok, [stored]} = Actions.list_credentials(strategy, user, [])
      assert byte_size(stored.user_handle) == 32

      assert {:ok, _} = sign_in(strategy, credential, email, user_handle: stored.user_handle)

      assert {:error, %AuthenticationFailed{} = error} =
               sign_in(strategy, credential, email, user_handle: :crypto.strong_rand_bytes(32))

      assert error.caused_by.message =~ "user handle"
    end

    test "user_verification \"required\" is enforced at registration and sign-in", %{
      strategy: strategy
    } do
      required = %{strategy | user_verification: "required"}

      assert {:error, %AuthenticationFailed{}} =
               register_result(required, "uv-register@example.com", uv: false)

      {_user, credential} = register(required, "uv-sign-in@example.com", uv: true)

      assert {:error, %AuthenticationFailed{}} =
               sign_in(required, credential, "uv-sign-in@example.com", uv: false)

      assert {:ok, _} = sign_in(required, credential, "uv-sign-in@example.com", uv: true)
    end

    test "timeout is enforced from the rebuilt challenge", %{strategy: strategy} do
      email = "timeout@example.com"
      {_user, credential} = register(strategy, email)

      assert {:error, %AuthenticationFailed{}} =
               sign_in(strategy, credential, email, challenge_age: 90)

      patient = %{strategy | timeout: 300_000}
      assert {:ok, _} = sign_in(patient, credential, email, challenge_age: 200)
    end

    test "the origin policy decides, not the request", %{strategy: strategy} do
      proxied = "http://10.0.0.5:4000"
      derived = %{strategy | origin: nil}

      assert {:ok, _} =
               round_trip(derived, "derived-ok@example.com",
                 origin: "https://app.example.com",
                 url: proxied
               )

      assert {:error, %AuthenticationFailed{}} =
               register_result(derived, "derived-evil@example.com",
                 origin: "https://evil.com",
                 url: proxied
               )

      assert {:error, %AuthenticationFailed{}} =
               register_result(derived, "derived-http@example.com",
                 origin: "http://app.example.com",
                 url: proxied
               )

      listed = %{strategy | origin: ["https://a.example.com"]}

      assert {:ok, _} =
               round_trip(listed, "listed-ok@example.com",
                 origin: "https://a.example.com",
                 url: proxied
               )

      assert {:error, %AuthenticationFailed{}} =
               register_result(listed, "listed-b@example.com",
                 origin: "https://b.example.com",
                 url: proxied
               )
    end
  end

  describe "through the actions" do
    test "register, sign in, verify and add a credential", %{strategy: strategy} do
      email = "actions@example.com"
      credential = Mock.new_credential()
      handle = :crypto.strong_rand_bytes(32)

      {:ok, challenge} = Actions.registration_challenge(strategy, nil)

      assert {:ok, user} =
               Actions.register(
                 strategy,
                 Map.put(
                   Mock.attestation(credential, Mock.challenge_bytes(challenge)),
                   "email",
                   email
                 ),
                 challenge: challenge,
                 user_handle: handle
               )

      {:ok, challenge} = Actions.authentication_challenge(strategy, [], nil)

      assert {:ok, signed_in} =
               Actions.sign_in(
                 strategy,
                 Map.put(
                   Mock.assertion(credential, Mock.challenge_bytes(challenge),
                     user_handle: handle
                   ),
                   "email",
                   email
                 ),
                 challenge: challenge
               )

      assert signed_in.id == user.id
      assert signed_in.__metadata__.token

      assert {:ok, _} =
               Actions.sign_in_with_token(
                 strategy,
                 %{"token" => signed_in.__metadata__.token},
                 []
               )

      allowed = [{credential.credential_id, Mock.public_key(credential)}]
      {:ok, challenge} = Actions.authentication_challenge(strategy, allowed, nil)

      assert {:ok, verified} =
               Actions.verify(
                 strategy,
                 Mock.assertion(credential, Mock.challenge_bytes(challenge), sign_count: 2),
                 challenge: challenge,
                 actor: user
               )

      assert %DateTime{} = verified.__metadata__.webauthn_verified_at

      second = Mock.new_credential()
      {:ok, challenge} = Actions.registration_challenge(strategy, nil)

      assert {:ok, added} =
               Actions.add_credential(
                 strategy,
                 Map.put(
                   Mock.attestation(second, Mock.challenge_bytes(challenge)),
                   "label",
                   "Second"
                 ),
                 challenge: challenge,
                 user: user,
                 user_handle: handle
               )

      assert added.credential_id == second.credential_id
      assert added.user_handle == handle
    end

    test "list, relabel and delete credentials, keeping the last one", %{strategy: strategy} do
      {user, _first} = register(strategy, "manage@example.com")
      second = Mock.new_credential()
      {:ok, challenge} = Actions.registration_challenge(strategy, nil)

      {:ok, _} =
        Actions.add_credential(
          strategy,
          Mock.attestation(second, Mock.challenge_bytes(challenge)),
          challenge: challenge,
          user: user
        )

      {:ok, [first_stored, second_stored]} = Actions.list_credentials(strategy, user, [])
      assert second_stored.credential_id == second.credential_id

      assert {:ok, relabelled} =
               Actions.update_credential_label(strategy, second_stored.id, "Renamed", [])

      assert relabelled.label == "Renamed"

      assert :ok = Actions.delete_credential(strategy, user, first_stored.id, [])
      {:ok, [remaining]} = Actions.list_credentials(strategy, user, [])
      assert remaining.id == second_stored.id

      assert {:error, %AuthenticationFailed{}} =
               Actions.delete_credential(strategy, user, remaining.id, [])
    end

    test "sign_count_policy :reject refuses a count that did not increase", %{strategy: strategy} do
      {strategy, user, credential, email} = count_fixture(strategy, :reject)

      assert {:error, %AuthenticationFailed{} = error} =
               sign_in_via_actions(strategy, credential, email, sign_count: 5)

      assert error.caused_by.message =~ "Sign count did not increase"
      assert stored_count(strategy, user) == 5

      # A count that did increase is fine
      assert {:ok, _} = sign_in_via_actions(strategy, credential, email, sign_count: 10)
      assert stored_count(strategy, user) == 10
    end

    test "sign_count_policy :log allows it but keeps the high-water mark", %{strategy: strategy} do
      {strategy, user, credential, email} = count_fixture(strategy, :log)

      assert {:ok, _} = sign_in_via_actions(strategy, credential, email, sign_count: 5)
      assert stored_count(strategy, user) == 5

      assert {:ok, _} = sign_in_via_actions(strategy, credential, email, sign_count: 10)
      assert stored_count(strategy, user) == 10
    end

    test "sign_count_policy :ignore overwrites the stored count", %{strategy: strategy} do
      {strategy, user, credential, email} = count_fixture(strategy, :ignore)

      assert {:ok, _} = sign_in_via_actions(strategy, credential, email, sign_count: 5)
      assert {:ok, _} = sign_in_via_actions(strategy, credential, email, sign_count: 3)
      assert stored_count(strategy, user) == 3
    end
  end

  # A registered user whose credential has been used once, at count 5, under
  # the given policy — so the next assertion at 5 is the clone signal.
  defp count_fixture(strategy, policy) do
    strategy = %{strategy | sign_count_policy: policy}
    email = "count-#{policy}@example.com"
    {user, credential} = register(strategy, email)

    assert {:ok, _} = sign_in_via_actions(strategy, credential, email, sign_count: 5)
    assert stored_count(strategy, user) == 5

    {strategy, user, credential, email}
  end

  # --- helpers --------------------------------------------------------------

  defp body(conn), do: Jason.decode!(conn.resp_body)

  defp challenge_bytes(conn),
    do: conn |> body() |> Map.fetch!("challenge") |> Base.url_decode64!(padding: false)

  defp assertion(credential, challenge_conn, opts \\ []),
    do: Mock.assertion(credential, challenge_bytes(challenge_conn), opts)

  # GET a challenge. `opts`: `:actor`, `:tenant`, `:url` (the request's base URL).
  defp challenge(strategy, phase, params, opts \\ []) do
    :get
    |> conn("#{Keyword.get(opts, :url, "")}/#{@subject}/webauthn/#{phase}", params)
    |> prepare(opts)
    |> plug(phase, strategy)
  end

  # POST the answer to `challenge_conn`, transplanting its session entry (the
  # test SessionPipeline mints a fresh secret per conn, so cookies can't
  # round-trip). `:challenge_age` backdates the stored challenge.
  defp answer(strategy, phase, challenge_conn, session_key, params, opts \\ []) do
    session_data =
      challenge_conn
      |> Plug.Conn.get_session(session_key)
      |> Map.update!("issued_at", &(&1 - Keyword.get(opts, :challenge_age, 0)))

    :post
    |> conn("#{Keyword.get(opts, :url, "")}/#{@subject}/webauthn/#{phase}", %{@subject => params})
    |> prepare(opts)
    |> Plug.Conn.put_session(session_key, session_data)
    |> plug(phase, strategy)
  end

  defp prepare(conn, opts) do
    conn = SessionPipeline.call(conn, [])
    conn = if actor = opts[:actor], do: Ash.PlugHelpers.set_actor(conn, actor), else: conn
    if tenant = opts[:tenant], do: Ash.PlugHelpers.set_tenant(conn, tenant), else: conn
  end

  defp plug(phase, strategy), do: fn conn -> apply(WebAuthn.Plug, phase, [conn, strategy]) end
  defp plug(conn, phase, strategy), do: plug(phase, strategy).(conn)

  @response_opts [:origin, :rp_id, :uv, :up, :be, :bs, :sign_count, :user_handle, :key]

  # Run the registration ceremony for a fresh mock credential; returns the
  # plug's result and the credential that answered.
  defp attempt_register(strategy, email, opts) do
    challenge_conn = challenge(strategy, :registration_challenge, %{"email" => email}, opts)
    credential = Mock.new_credential()

    params =
      credential
      |> Mock.attestation(challenge_bytes(challenge_conn), Keyword.take(opts, @response_opts))
      |> Map.put("email", email)

    conn = answer(strategy, :register, challenge_conn, @attestation_key, params, opts)
    {conn.private[:authentication_result], credential}
  end

  defp register(strategy, email, opts \\ []) do
    {result, credential} = attempt_register(strategy, email, opts)
    assert {:ok, user} = result
    {user, credential}
  end

  defp register_result(strategy, email, opts),
    do: attempt_register(strategy, email, opts) |> elem(0)

  defp sign_in(strategy, credential, email, opts \\ []) do
    challenge_conn = challenge(strategy, :authentication_challenge, %{"email" => email}, opts)

    params =
      credential
      |> Mock.assertion(challenge_bytes(challenge_conn), Keyword.take(opts, @response_opts))
      |> Map.put("email", email)

    answer(strategy, :sign_in, challenge_conn, @authentication_key, params, opts).private[
      :authentication_result
    ]
  end

  defp round_trip(strategy, email, opts) do
    case attempt_register(strategy, email, opts) do
      {{:ok, _user}, credential} -> sign_in(strategy, credential, email, opts)
      {error, _credential} -> error
    end
  end

  defp sign_in_via_actions(strategy, credential, email, opts) do
    {:ok, challenge} = Actions.authentication_challenge(strategy, [], nil)

    Actions.sign_in(
      strategy,
      Map.put(Mock.assertion(credential, Mock.challenge_bytes(challenge), opts), "email", email),
      challenge: challenge
    )
  end

  defp stored_count(strategy, user) do
    {:ok, [credential]} = Actions.list_credentials(strategy, user, [])
    credential.sign_count
  end
end
