# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.CustomStrategyNamesTest do
  @moduledoc """
  Strategies that rename what the `webauthn` DSL lets them rename, and a
  resource with two `webauthn` strategies, run through every ceremony.

  - **Renamed:** `identity_field :username` instead of `:email`; all four
    action names; the `credentials_relationship_name`.
  - **Two strategies:** a primary passkey strategy, and a second-factor
    security-key strategy with its own authenticator options, sharing one
    credential resource.
  """
  use DataCase, async: false

  import Plug.Test

  alias AshAuthentication.{Info, Strategy}
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.{WebAuthnCeremony, WebAuthnFixtures}

  @moduletag feature: :webauthn

  setup_all do
    suffix = System.unique_integer([:positive])
    base = "AshAuthentication.Strategy.WebAuthn.CustomStrategyNamesTest"

    renamed_user = "#{base}.RenamedUser#{suffix}"
    renamed_credential = "#{base}.RenamedCredential#{suffix}"
    dual_user = "#{base}.DualUser#{suffix}"
    dual_credential = "#{base}.DualCredential#{suffix}"

    # Each user resource is compiled before its credential resource: the
    # credential extension reads the user's primary key.
    Code.compile_string("""
    defmodule #{renamed_user} do
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
        attribute :username, :ci_string, allow_nil?: false, public?: true
      end

      identities do
        identity :unique_username, [:username],
          pre_check_with: AshAuthentication.Test.PermissiveDomain
      end

      actions do
        defaults [:read]
      end

      relationships do
        has_many :passkeys, #{renamed_credential},
          destination_attribute: :renamed_user#{suffix}_id
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
          webauthn :passkey do
            credential_resource #{renamed_credential}
            rp_id "example.com"
            rp_name "Test App"
            origin "https://example.com"
            identity_field :username
            credentials_relationship_name :passkeys
            register_action_name :sign_up_with_passkey
            sign_in_action_name :log_in_with_passkey
            sign_in_with_token_action_name :exchange_passkey_token
            verify_action_name :step_up_with_passkey
          end
        end
      end
    end

    defmodule #{renamed_credential} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.WebAuthnCredential]

      ets do
        private?(true)
      end

      webauthn_credential do
        user_resource #{renamed_user}
        user_relationship_name :renamed_user#{suffix}
      end
    end
    """)

    Code.compile_string("""
    defmodule #{dual_user} do
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
        attribute :email, :ci_string, allow_nil?: false, public?: true
      end

      identities do
        identity :unique_email, [:email],
          pre_check_with: AshAuthentication.Test.PermissiveDomain
      end

      actions do
        defaults [:read]
      end

      relationships do
        has_many :webauthn_credentials, #{dual_credential},
          destination_attribute: :dual_user#{suffix}_id
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
          webauthn :passkey do
            credential_resource #{dual_credential}
            rp_id "example.com"
            rp_name "Test App"
            origin "https://example.com"
          end

          webauthn :security_key do
            credential_resource #{dual_credential}
            rp_id "example.com"
            rp_name "Test App"
            origin "https://example.com"
            registration_enabled? false
            sign_in_enabled? false
            resident_key :discouraged
            authenticator_attachment :cross_platform
            user_verification "discouraged"
          end
        end
      end
    end

    defmodule #{dual_credential} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.WebAuthnCredential]

      ets do
        private?(true)
      end

      webauthn_credential do
        user_resource #{dual_user}
        user_relationship_name :dual_user#{suffix}
      end
    end
    """)

    renamed = Module.concat([renamed_user])
    dual = Module.concat([dual_user])

    %{
      renamed: Info.strategy!(renamed, :passkey),
      renamed_resource: renamed,
      passkey: Info.strategy!(dual, :passkey),
      security_key: Info.strategy!(dual, :security_key),
      dual_resource: dual
    }
  end

  describe "renamed actions, identity field and relationship" do
    test "the actions are built under the configured names", ctx do
      for name <- [
            :sign_up_with_passkey,
            :log_in_with_passkey,
            :exchange_passkey_token,
            :step_up_with_passkey
          ] do
        assert Ash.Resource.Info.action(ctx.renamed_resource, name),
               "expected the `#{name}` action"
      end

      for default <- [
            :register_with_passkey,
            :sign_in_with_passkey,
            :sign_in_with_passkey_token,
            :verify_passkey
          ] do
        refute Ash.Resource.Info.action(ctx.renamed_resource, default)
      end

      assert %{type: :has_many} = Ash.Resource.Info.relationship(ctx.renamed_resource, :passkeys)
      refute Ash.Resource.Info.relationship(ctx.renamed_resource, :webauthn_credentials)
    end

    test "registration takes and stores the custom identity field", ctx do
      {result, _passkey} =
        WebAuthnCeremony.register(ctx.renamed, %{"username" => "ada"})

      assert {:ok, user} = result
      assert to_string(user.username) == "ada"
      assert {:ok, [_credential]} = Actions.list_credentials(ctx.renamed, user, [])
    end

    test "sign-in, the token exchange and verify run through the renamed actions", ctx do
      {{:ok, user}, passkey} =
        WebAuthnCeremony.register(ctx.renamed, %{"username" => "grace"})

      assert {:ok, signed_in} =
               WebAuthnCeremony.sign_in(ctx.renamed, passkey, %{"username" => "grace"})

      assert signed_in.id == user.id

      assert {:ok, exchanged} =
               Actions.sign_in_with_token(ctx.renamed, %{
                 "token" => signed_in.__metadata__.token
               })

      assert exchanged.id == user.id
      assert exchanged.__metadata__.token

      assert {:ok, verified} = WebAuthnCeremony.verify(ctx.renamed, user, passkey)
      assert %DateTime{} = verified.__metadata__.webauthn_verified_at
    end

    test "a submitted identity is checked under the custom field name", ctx do
      {{:ok, _user}, passkey} =
        WebAuthnCeremony.register(ctx.renamed, %{"username" => "linus"})

      {{:ok, _other}, _} = WebAuthnCeremony.register(ctx.renamed, %{"username" => "ken"})

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               WebAuthnCeremony.sign_in(ctx.renamed, passkey, %{"username" => "ken"})
    end
  end

  describe "two webauthn strategies on one resource" do
    test "each gets its own actions, sharing one credentials relationship", ctx do
      assert Ash.Resource.Info.action(ctx.dual_resource, :register_with_passkey)
      assert Ash.Resource.Info.action(ctx.dual_resource, :sign_in_with_passkey)
      assert Ash.Resource.Info.action(ctx.dual_resource, :verify_passkey)
      assert Ash.Resource.Info.action(ctx.dual_resource, :verify_security_key)
      refute Ash.Resource.Info.action(ctx.dual_resource, :register_with_security_key)
      refute Ash.Resource.Info.action(ctx.dual_resource, :sign_in_with_security_key)
      # The second-factor strategy keeps its own exchange for its verify token.
      assert Ash.Resource.Info.action(ctx.dual_resource, :sign_in_with_security_key_token)

      assert Strategy.phases(ctx.security_key) == [
               :sign_in_with_token,
               :verify_challenge,
               :verify,
               :add_credential_challenge,
               :add_credential
             ]
    end

    test "a user registered through one can enrol and verify through the other", ctx do
      {{:ok, user}, _passkey} =
        WebAuthnCeremony.register(ctx.passkey, %{"email" => "dual@example.com"})

      {{:ok, _credential}, security_key} =
        WebAuthnCeremony.add_credential(ctx.security_key, user)

      assert {:ok, credentials} = Actions.list_credentials(ctx.security_key, user, [])
      assert length(credentials) == 2

      assert {:ok, verified} = WebAuthnCeremony.verify(ctx.security_key, user, security_key)
      assert verified.id == user.id
    end

    test "each strategy offers its own authenticator options", ctx do
      passkey_options = registration_options(ctx.passkey)
      security_key_options = registration_options(ctx.security_key)

      assert passkey_options["authenticatorSelection"]["residentKey"] == "required"
      refute Map.has_key?(passkey_options["authenticatorSelection"], "authenticatorAttachment")

      assert security_key_options["authenticatorSelection"]["residentKey"] == "discouraged"
      assert security_key_options["authenticatorSelection"]["requireResidentKey"] == false

      assert security_key_options["authenticatorSelection"]["authenticatorAttachment"] ==
               "cross-platform"

      assert security_key_options["authenticatorSelection"]["userVerification"] ==
               "discouraged"
    end

    test "a challenge issued by one strategy can't be answered through the other", ctx do
      {{:ok, user}, passkey} =
        WebAuthnCeremony.register(ctx.passkey, %{"email" => "isolated@example.com"})

      challenge_conn =
        :get
        |> conn("https://example.com/dual/passkey/verify_challenge", %{})
        |> SessionPipeline.call([])
        |> Ash.PlugHelpers.set_actor(user)
        |> WebAuthn.Plug.verify_challenge(ctx.passkey)

      assert challenge_conn.status == 200
      session = challenge_conn |> Plug.Conn.fetch_session() |> Plug.Conn.get_session()
      assert Map.has_key?(session, "webauthn_authentication_challenge_passkey")

      assertion =
        WebAuthnFixtures.generate_authentication(passkey,
          challenge_bytes: challenge_bytes(challenge_conn),
          origin: "https://example.com",
          sign_count: 1
        )

      conn =
        :post
        |> conn("https://example.com/dual/security_key/verify", %{
          subject_name(ctx.dual_resource) => %{
            "raw_id" => Base.url_encode64(assertion.raw_id, padding: false),
            "authenticator_data" => assertion.authenticator_data,
            "signature" => assertion.signature,
            "client_data_json" => assertion.client_data_json
          }
        })
        |> SessionPipeline.call([])
        |> then(fn conn ->
          Enum.reduce(session, conn, &Plug.Conn.put_session(&2, elem(&1, 0), elem(&1, 1)))
        end)
        |> Ash.PlugHelpers.set_actor(user)
        |> WebAuthn.Plug.verify(ctx.security_key)

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               conn.private[:authentication_result]

      # The passkey strategy's challenge is still pending, untouched.
      assert Plug.Conn.get_session(conn, "webauthn_authentication_challenge_passkey")
    end
  end

  defp registration_options(strategy) do
    :get
    |> conn("https://example.com/dual/#{strategy.name}/registration_challenge", %{
      "email" => "options@example.com"
    })
    |> SessionPipeline.call([])
    |> WebAuthn.Plug.registration_challenge(strategy)
    |> Map.fetch!(:resp_body)
    |> Jason.decode!()
  end

  defp challenge_bytes(conn) do
    conn.resp_body
    |> Jason.decode!()
    |> Map.fetch!("challenge")
    |> Base.url_decode64!(padding: false)
  end

  defp subject_name(resource), do: resource |> Info.authentication_subject_name!() |> to_string()
end
