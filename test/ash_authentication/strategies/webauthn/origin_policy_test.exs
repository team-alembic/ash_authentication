# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.OriginPolicyTest do
  @moduledoc """
  The origin a ceremony is accepted from is the strategy's policy, never the
  request's own scheme, host and port. Every round trip here asks for its
  challenge on `http://10.0.0.5:4000` — what a TLS-terminating proxy hands
  the app — while the browser signs the origin it really used.
  """
  use DataCase, async: false

  import Plug.Test

  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

  @rp_id "example.com"
  @proxied "http://10.0.0.5:4000"
  @attestation_key "webauthn_attestation_challenge_webauthn"
  @authentication_key "webauthn_authentication_challenge_webauthn"

  setup do
    # `Example.UserWithWebAuthn` configures `origin "https://example.com"`;
    # each test states the policy it is about on its own copy of the strategy.
    %{strategy: Info.strategy!(Example.UserWithWebAuthn, :webauthn)}
  end

  describe "with no origin configured (derived from the rp_id)" do
    setup %{strategy: strategy}, do: %{strategy: %{strategy | origin: nil, rp_id: @rp_id}}

    test "https on a subdomain of the rp_id passes, whatever the request said", %{
      strategy: strategy
    } do
      assert {:ok, user} = round_trip(strategy, "https://app.example.com", "sub@example.com")
      assert to_string(user.email) == "sub@example.com"
    end

    test "https on the rp_id itself passes", %{strategy: strategy} do
      assert {:ok, _} = round_trip(strategy, "https://example.com", "apex@example.com")
    end

    test "a non-standard port passes", %{strategy: strategy} do
      assert {:ok, _} = round_trip(strategy, "https://example.com:4001", "port@example.com")
    end

    test "another host is rejected at registration and at sign-in", %{strategy: strategy} do
      assert {:error, %AuthenticationFailed{}} =
               register(strategy, "https://evil.com", "evil-register@example.com")

      passkey = register!(strategy, "https://app.example.com", "evil-sign-in@example.com")

      assert {:error, %AuthenticationFailed{}} =
               sign_in(strategy, passkey, "https://evil.com", "evil-sign-in@example.com")
    end

    test "http on the rp_id is rejected at registration and at sign-in", %{strategy: strategy} do
      assert {:error, %AuthenticationFailed{}} =
               register(strategy, "http://app.example.com", "http-register@example.com")

      passkey = register!(strategy, "https://app.example.com", "http-sign-in@example.com")

      assert {:error, %AuthenticationFailed{}} =
               sign_in(strategy, passkey, "http://app.example.com", "http-sign-in@example.com")
    end

    test "http://localhost passes when the rp_id is localhost", %{strategy: strategy} do
      strategy = %{strategy | rp_id: "localhost"}

      assert {:ok, _} =
               round_trip(strategy, "http://localhost:4000", "localhost@example.com",
                 rp_id: "localhost"
               )
    end
  end

  describe "with a configured allowlist" do
    setup %{strategy: strategy},
      do: %{strategy: %{strategy | origin: ["https://a.example.com"], rp_id: @rp_id}}

    test "a listed origin passes whatever the request host is", %{strategy: strategy} do
      assert {:ok, _} = round_trip(strategy, "https://a.example.com", "listed@example.com")
    end

    test "an unlisted origin under the same rp_id is rejected", %{strategy: strategy} do
      assert {:error, %AuthenticationFailed{}} =
               register(strategy, "https://b.example.com", "unlisted-register@example.com")

      passkey = register!(strategy, "https://a.example.com", "unlisted-sign-in@example.com")

      assert {:error, %AuthenticationFailed{}} =
               sign_in(strategy, passkey, "https://b.example.com", "unlisted-sign-in@example.com")
    end

    test "the list is exact down to the port", %{strategy: strategy} do
      assert {:error, %AuthenticationFailed{}} =
               register(strategy, "https://a.example.com:4001", "port-register@example.com")
    end

    test "a single string is a one-entry allowlist", %{strategy: strategy} do
      strategy = %{strategy | origin: "https://a.example.com"}
      assert {:ok, _} = round_trip(strategy, "https://a.example.com", "string@example.com")

      assert {:error, %AuthenticationFailed{}} =
               register(strategy, "https://b.example.com", "string-rejected@example.com")
    end
  end

  describe "with a per-tenant origin function" do
    setup %{strategy: strategy} do
      %{
        strategy: %{
          strategy
          | rp_id: @rp_id,
            origin: fn tenant -> ["https://#{tenant}.example.com"] end
        }
      }
    end

    test "the tenant's origin passes and another tenant's is rejected", %{strategy: strategy} do
      assert {:ok, _} =
               round_trip(strategy, "https://acme.example.com", "acme@example.com",
                 tenant: "acme"
               )

      assert {:error, %AuthenticationFailed{}} =
               register(strategy, "https://globex.example.com", "globex-as-acme@example.com",
                 tenant: "acme"
               )

      passkey =
        register!(strategy, "https://acme.example.com", "acme-sign-in@example.com",
          tenant: "acme"
        )

      assert {:error, %AuthenticationFailed{}} =
               sign_in(
                 strategy,
                 passkey,
                 "https://globex.example.com",
                 "acme-sign-in@example.com",
                 tenant: "acme"
               )
    end
  end

  describe "the stored challenge" do
    test "carries the policy, not the request's origin", %{strategy: strategy} do
      strategy = %{strategy | origin: nil, rp_id: @rp_id}
      conn = registration_challenge_conn(strategy, "stored@example.com", [])
      stored = Plug.Conn.get_session(conn, @attestation_key)

      assert stored.origin == %{rp_id: @rp_id}

      strategy = %{strategy | origin: ["https://a.example.com"]}
      conn = registration_challenge_conn(strategy, "stored2@example.com", [])

      assert Plug.Conn.get_session(conn, @attestation_key).origin == %{
               allow: ["https://a.example.com"]
             }
    end
  end

  # Register, then sign in, both from `client_origin`.
  defp round_trip(strategy, client_origin, email, opts \\ []) do
    with {:ok, _user} <- register(strategy, client_origin, email, opts) do
      sign_in(strategy, Process.get({:passkey, email}), client_origin, email, opts)
    end
  end

  defp register!(strategy, client_origin, email, opts \\ []) do
    assert {:ok, _} = register(strategy, client_origin, email, opts)
    Process.get({:passkey, email})
  end

  defp register(strategy, client_origin, email, opts \\ []) do
    challenge_conn = registration_challenge_conn(strategy, email, opts)

    passkey =
      WebAuthnFixtures.generate_registration(
        origin: client_origin,
        rp_id: Keyword.get(opts, :rp_id, @rp_id),
        challenge_bytes: challenge_bytes(challenge_conn)
      )

    Process.put({:passkey, email}, passkey)

    :post
    |> conn("#{@proxied}/user_with_web_authn/webauthn/register", %{
      "user_with_web_authn" => %{
        "email" => email,
        "attestation_object" => passkey.attestation_object,
        "client_data_json" => passkey.client_data_json,
        "raw_id" => passkey.raw_id
      }
    })
    |> prepare(opts)
    |> Plug.Conn.put_session(
      @attestation_key,
      Plug.Conn.get_session(challenge_conn, @attestation_key)
    )
    |> WebAuthn.Plug.register(strategy)
    |> Map.fetch!(:private)
    |> Map.fetch!(:authentication_result)
  end

  defp sign_in(strategy, passkey, client_origin, email, opts \\ []) do
    challenge_conn =
      :get
      |> conn("#{@proxied}/user_with_web_authn/webauthn/authentication_challenge", %{})
      |> prepare(opts)
      |> WebAuthn.Plug.authentication_challenge(strategy)

    assertion =
      WebAuthnFixtures.generate_authentication(passkey,
        origin: client_origin,
        rp_id: Keyword.get(opts, :rp_id, @rp_id),
        challenge_bytes: challenge_bytes(challenge_conn),
        sign_count: 1
      )

    :post
    |> conn("#{@proxied}/user_with_web_authn/webauthn/sign_in", %{
      "user_with_web_authn" => %{
        "email" => email,
        "raw_id" => Base.url_encode64(assertion.raw_id, padding: false),
        "authenticator_data" => assertion.authenticator_data,
        "signature" => assertion.signature,
        "client_data_json" => assertion.client_data_json
      }
    })
    |> prepare(opts)
    |> Plug.Conn.put_session(
      @authentication_key,
      Plug.Conn.get_session(challenge_conn, @authentication_key)
    )
    |> WebAuthn.Plug.sign_in(strategy)
    |> Map.fetch!(:private)
    |> Map.fetch!(:authentication_result)
  end

  defp registration_challenge_conn(strategy, email, opts) do
    :get
    |> conn("#{@proxied}/user_with_web_authn/webauthn/registration_challenge", %{"email" => email})
    |> prepare(opts)
    |> WebAuthn.Plug.registration_challenge(strategy)
  end

  # The request arrives as the proxy forwarded it: plain http, internal host.
  defp prepare(conn, opts) do
    assert conn.scheme == :http
    assert conn.host == "10.0.0.5"
    assert conn.port == 4000

    conn = SessionPipeline.call(conn, [])

    case Keyword.get(opts, :tenant) do
      nil -> conn
      tenant -> Ash.PlugHelpers.set_tenant(conn, tenant)
    end
  end

  defp challenge_bytes(challenge_conn) do
    challenge_conn.resp_body
    |> Jason.decode!()
    |> Map.fetch!("challenge")
    |> Base.url_decode64!(padding: false)
  end
end
