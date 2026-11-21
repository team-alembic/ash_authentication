# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.ActionContextTest do
  @moduledoc """
  The caller's Ash context reaches the action each WebAuthn phase runs.

  A plug sets it with `Ash.PlugHelpers.set_context/2`; a direct caller passes
  `context:`. Either way a change or preparation declared on the resource
  reads it from the changeset or query, as it does on the Password strategy.
  The resources here record the context every create and read runs with, and
  the register action copies `invitation_token` out of it: the shape of an
  invitation-only registration.
  """
  use DataCase, async: false

  import Plug.Test

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.{WebAuthnCeremony, WebAuthnFixtures}

  @moduletag feature: :webauthn

  setup_all do
    suffix = System.unique_integer([:positive])
    base = "AshAuthentication.Strategy.WebAuthn.ActionContextTest"
    user = "#{base}.User#{suffix}"
    credential = "#{base}.Credential#{suffix}"

    Code.compile_string("""
    defmodule #{user} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication]

      ets do
        private?(true)
      end

      attributes do
        uuid_primary_key :id
        attribute :invitation_token, :string, public?: true
      end

      actions do
        defaults [:read]
      end

      # Resource-level, so they run on the actions the strategy generates.
      changes do
        change fn changeset, _ ->
          send(self(), {:create_context, changeset.action.name, changeset.context})

          Ash.Changeset.force_change_attribute(
            changeset,
            :invitation_token,
            changeset.context[:invitation_token]
          )
        end, on: [:create]
      end

      preparations do
        prepare fn query, _ ->
          send(self(), {:read_context, query.action.name, query.context})
          query
        end
      end

      relationships do
        has_many :webauthn_credentials, #{credential},
          destination_attribute: :user#{suffix}_id
      end

      authentication do
        session_identifier(:jti)

        tokens do
          enabled? true
          store_all_tokens? true
          token_resource Example.Token
          signing_secret &Example.User.get_config/2
        end

        strategies do
          webauthn :webauthn do
            credential_resource #{credential}
            require_identity? false
            rp_id "example.com"
            rp_name "Test App"
            origin "https://example.com"
          end
        end
      end
    end

    defmodule #{credential} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.WebAuthnCredential]

      ets do
        private?(true)
      end

      changes do
        change fn changeset, _ ->
          send(self(), {:credential_context, changeset.action.name, changeset.context})
          changeset
        end, on: [:create]
      end

      webauthn_credential do
        user_resource #{user}
        user_relationship_name :user#{suffix}
      end
    end
    """)

    resource = Module.concat([user])

    %{
      strategy: Info.strategy!(resource, :webauthn),
      subject: resource |> Info.authentication_subject_name!() |> to_string()
    }
  end

  describe "through Actions" do
    test "register: the context is on the register action's changeset", ctx do
      {{:ok, user}, _passkey} =
        WebAuthnCeremony.register(ctx.strategy, %{}, context: %{invitation_token: "inv-1"})

      assert user.invitation_token == "inv-1"

      assert_received {:create_context, :register_with_webauthn, context}
      assert context.invitation_token == "inv-1"
      # The strategy's own context is still there, over the caller's.
      assert context.private.ash_authentication? == true
      assert context.token_type == :sign_in
    end

    test "register: a keyword list works too", ctx do
      {{:ok, user}, _passkey} =
        WebAuthnCeremony.register(ctx.strategy, %{}, context: [invitation_token: "inv-kw"])

      assert user.invitation_token == "inv-kw"
    end

    test "register: a caller's private and shared.private are dropped", ctx do
      context = %{
        private: %{ash_authentication?: false, planted: true},
        shared: %{private: %{planted: true}, request_id: "r1"}
      }

      {{:ok, _user}, _passkey} = WebAuthnCeremony.register(ctx.strategy, %{}, context: context)

      assert_received {:create_context, :register_with_webauthn, context}
      assert context.private.ash_authentication? == true
      refute Map.has_key?(context.private, :planted)
      refute Map.has_key?(context.shared.private, :planted)
      # The rest of the caller's shared context is kept.
      assert context.shared.request_id == "r1"
    end

    test "register: nothing changes without a context", ctx do
      {{:ok, user}, _passkey} = WebAuthnCeremony.register(ctx.strategy)

      assert is_nil(user.invitation_token)
      assert_received {:create_context, :register_with_webauthn, context}
      refute Map.has_key?(context, :invitation_token)
      assert context.private.ash_authentication? == true
    end

    test "sign_in: the context is on the sign-in action's query", ctx do
      {{:ok, _user}, passkey} = WebAuthnCeremony.register(ctx.strategy)

      assert {:ok, _signed_in} =
               WebAuthnCeremony.sign_in(ctx.strategy, passkey, %{}, context: %{request_id: "r2"})

      assert_received {:read_context, :sign_in_with_webauthn, context}
      assert context.request_id == "r2"
      assert context.private.ash_authentication? == true
      assert %{} = context.private[WebAuthn.CeremonyUser.context_key()]
    end

    test "sign_in_with_token: the context is on the exchange action's query", ctx do
      {{:ok, _user}, passkey} = WebAuthnCeremony.register(ctx.strategy)
      {:ok, signed_in} = WebAuthnCeremony.sign_in(ctx.strategy, passkey)

      assert {:ok, _user} =
               Actions.sign_in_with_token(
                 ctx.strategy,
                 %{"token" => signed_in.__metadata__.token},
                 context: %{request_id: "r3", private: %{planted: true}}
               )

      assert_received {:read_context, :sign_in_with_webauthn_token, context}
      assert context.request_id == "r3"
      assert context.private.ash_authentication? == true
      refute Map.has_key?(context.private, :planted)
    end

    test "verify: the context is on the verify action's query", ctx do
      {{:ok, user}, passkey} = WebAuthnCeremony.register(ctx.strategy)

      assert {:ok, _verified} =
               WebAuthnCeremony.verify(ctx.strategy, user, passkey, context: %{request_id: "r4"})

      assert_received {:read_context, :verify_webauthn, context}
      assert context.request_id == "r4"
      assert context.private.ash_authentication? == true
      assert %DateTime{} = context.private.webauthn_verified_at
    end

    test "add_credential: the context is on the credential's create changeset", ctx do
      {{:ok, user}, _passkey} = WebAuthnCeremony.register(ctx.strategy)

      assert {{:ok, _credential}, _passkey} =
               WebAuthnCeremony.add_credential(ctx.strategy, user, context: %{request_id: "r5"})

      # Registration created the first credential through the managed
      # relationship; this is the one add_credential created directly.
      assert_received {:credential_context, :create, %{request_id: "r5"} = context}
      assert context.private.ash_authentication? == true
    end
  end

  describe "through the plugs" do
    test "register: what Ash.PlugHelpers.set_context put on the conn reaches the action", ctx do
      challenge_conn = registration_challenge_conn(ctx)

      conn =
        ctx
        |> register_conn(challenge_conn)
        |> Ash.PlugHelpers.set_context(%{invitation_token: "inv-plug"})
        |> WebAuthn.Plug.register(ctx.strategy)

      assert {:ok, user} = conn.private[:authentication_result]
      assert user.invitation_token == "inv-plug"

      assert_received {:create_context, :register_with_webauthn, context}
      assert context.invitation_token == "inv-plug"
      assert context.private.ash_authentication? == true
    end

    test "register: a conn without a context registers as before", ctx do
      challenge_conn = registration_challenge_conn(ctx)

      conn =
        ctx
        |> register_conn(challenge_conn)
        |> WebAuthn.Plug.register(ctx.strategy)

      assert {:ok, user} = conn.private[:authentication_result]
      assert is_nil(user.invitation_token)
    end

    test "sign_in: the conn's context reaches the sign-in action", ctx do
      challenge_conn = registration_challenge_conn(ctx)
      {register_conn, passkey} = register_conn_and_passkey(ctx, challenge_conn)

      assert {:ok, _user} =
               WebAuthn.Plug.register(register_conn, ctx.strategy).private[:authentication_result]

      sign_in_challenge_conn =
        :get
        |> conn("/#{ctx.subject}/webauthn/authentication_challenge", %{})
        |> SessionPipeline.call([])
        |> WebAuthn.Plug.authentication_challenge(ctx.strategy)

      assertion =
        WebAuthnFixtures.generate_authentication(passkey,
          challenge_bytes: challenge_bytes(sign_in_challenge_conn),
          origin: "https://example.com"
        )

      conn =
        :post
        |> conn("/#{ctx.subject}/webauthn/sign_in", %{
          ctx.subject => %{
            "raw_id" => Base.url_encode64(assertion.raw_id, padding: false),
            "authenticator_data" => assertion.authenticator_data,
            "signature" => assertion.signature,
            "client_data_json" => assertion.client_data_json
          }
        })
        |> SessionPipeline.call([])
        |> Plug.Conn.put_session(
          "webauthn_authentication_challenge_webauthn",
          Plug.Conn.get_session(
            sign_in_challenge_conn,
            "webauthn_authentication_challenge_webauthn"
          )
        )
        |> Ash.PlugHelpers.set_context(%{request_id: "plug-r1"})
        |> WebAuthn.Plug.sign_in(ctx.strategy)

      assert {:ok, _user} = conn.private[:authentication_result]

      assert_received {:read_context, :sign_in_with_webauthn, context}
      assert context.request_id == "plug-r1"
      assert context.private.ash_authentication? == true
    end
  end

  @attestation_session_key "webauthn_attestation_challenge_webauthn"

  defp registration_challenge_conn(ctx) do
    :get
    |> conn("/#{ctx.subject}/webauthn/registration_challenge", %{})
    |> SessionPipeline.call([])
    |> WebAuthn.Plug.registration_challenge(ctx.strategy)
  end

  # A register POST answering the challenge `challenge_conn` issued, with that
  # conn's session entry transplanted (the test SessionPipeline mints a fresh
  # secret_key_base per conn, so cookies don't round-trip). Not yet run
  # through the plug, so a test can set its context first.
  defp register_conn(ctx, challenge_conn) do
    {conn, _passkey} = register_conn_and_passkey(ctx, challenge_conn)
    conn
  end

  defp register_conn_and_passkey(ctx, challenge_conn) do
    passkey =
      WebAuthnFixtures.generate_registration(
        origin: "https://example.com",
        rp_id: "example.com",
        challenge_bytes: challenge_bytes(challenge_conn)
      )

    conn =
      :post
      |> conn("/#{ctx.subject}/webauthn/register", %{
        ctx.subject => %{
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

    {conn, passkey}
  end

  defp challenge_bytes(challenge_conn) do
    challenge_conn.resp_body
    |> Jason.decode!()
    |> Map.fetch!("challenge")
    |> Base.url_decode64!(padding: false)
  end
end
