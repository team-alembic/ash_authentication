# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.VerifierTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias AshAuthentication.Strategy.WebAuthn.Verifier

  @moduletag feature: :webauthn

  @user_source """
  defmodule <%= user_module %> do
    @moduledoc false
    use Ash.Resource,
      domain: AshAuthentication.Test.PermissiveDomain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAuthentication]

    attributes do
      uuid_primary_key :id
      <%= user_attributes %>
    end

    <%= user_body %>

    ets do
      private?(true)
    end

    authentication do
      session_identifier(:jti)

      tokens do
        enabled? true
        token_resource Example.Token
        signing_secret &Example.User.get_config/2
      end

      strategies do
        webauthn :webauthn do
          credential_resource <%= credential_module %>
          rp_id "example.com"
          rp_name "Test App"
          <%= origin %>
          <%= identity_options %>
          <%= strategy_options %>
        end
      end
    end
  end
  """

  # An adapter whose backend isn't installed.
  defmodule UnavailableAdapter do
    @moduledoc false
    alias AshAuthentication.Strategy.WebAuthn.Adapter
    @behaviour Adapter

    @impl Adapter
    def check_dependencies, do: {:error, "The `:imaginary_fido` dependency is missing"}
    @impl Adapter
    def pub_key_cred_params, do: []
    @impl Adapter
    def registration_challenge(_strategy, _tenant, _opts), do: :challenge
    @impl Adapter
    def authentication_challenge(_strategy, _allow_credentials, _tenant, _opts), do: :challenge
    @impl Adapter
    def challenge_bytes(_challenge), do: <<>>
    @impl Adapter
    def serialize_challenge(_challenge), do: %{}
    @impl Adapter
    def deserialize_challenge(_strategy, _data, _type), do: nil
    @impl Adapter
    def verify_registration(_strategy, _attestation_object, _client_data_json, _challenge),
      do: {:error, :unavailable}

    @impl Adapter
    def verify_authentication(_strategy, _id, _auth_data, _sig, _client_data, _challenge, _creds),
      do: {:error, :unavailable}
  end

  describe "verify/2" do
    test "passes for valid configuration" do
      # Example.UserWithWebAuthn should compile without errors
      # The fact that it compiled means the verifier passed
      assert Example.UserWithWebAuthn.__info__(:module)
    end

    test "reports the adapter's missing dependency on the strategy that uses it" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(
            strategy_options:
              "adapter AshAuthentication.Strategy.WebAuthn.VerifierTest.UnavailableAdapter"
          )
        end)

      assert output =~ "The `:imaginary_fido` dependency is missing"
      assert output =~ "adapter"
    end

    test "accepts an origin allowlist" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(origin: ~s(origin ["https://a.example.com", "https://b.example.com:4001"]))
        end)

      refute output =~ "origin"
    end

    test "accepts no origin at all" do
      output = capture_io(:stderr, fn -> compile_pair(origin: "") end)
      refute output =~ "origin"
    end

    test "rejects a malformed origin" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(origin: ~s(origin ["https://a.example.com", "https://b.example.com/auth"]))
        end)

      assert output =~ "`origin` entries must be web origins"
      assert output =~ "https://b.example.com/auth"
    end

    test "rejects an empty origin list" do
      output = capture_io(:stderr, fn -> compile_pair(origin: "origin []") end)
      assert output =~ "would accept no origin at all"
    end

    # As of 5.0 the credential resource must use the `WebAuthnCredential`
    # extension — the strategy reads every credential field name and the
    # belongs-to name off its DSL, and Spark would otherwise hand back this
    # extension's defaults for a resource that never declared them.
    test "rejects a credential resource that doesn't use the WebAuthnCredential extension" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(
            credential_extensions: "",
            credential_body: """
              attributes do
                uuid_primary_key :id
              end
            """
          )
        end)

      assert output =~ "must use the `AshAuthentication.WebAuthnCredential` extension"
    end

    # The auto-built `has_many` derives its foreign key from the user
    # resource's name; the credential's `belongs_to` names its own. When the
    # two don't meet on the same column the relationship is silently broken,
    # so the verifier says so once the credential resource is compiled.
    test "rejects a credentials relationship that points at the wrong foreign key" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(user_relationship_name: ":owner")
        end)

      assert output =~ "webauthn_credentials"
      assert output =~ "destination_attribute :owner_id"
    end
  end

  describe "hints" do
    test "rejects roaming hints under authenticator_attachment :platform" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(
            strategy_options: """
            hints [:hybrid, :security_key]
            authenticator_attachment :platform
            timeout 300_000
            """
          )
        end)

      assert output =~ "contradicts `authenticator_attachment :platform`"
    end

    test "rejects :client_device under authenticator_attachment :cross_platform" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(
            strategy_options: """
            hints [:client_device]
            authenticator_attachment :cross_platform
            """
          )
        end)

      assert output =~ "contradicts `authenticator_attachment :cross_platform`"
    end

    # A cross-device ceremony has to fit a QR scan and a prompt on the second
    # device inside the timeout, which the 60s default cannot do.
    test "warns when :hybrid is offered with a timeout too short to scan a QR code" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(strategy_options: "hints [:hybrid]")
        end)

      assert output =~ "offers the `:hybrid` hint with `timeout 60000`"
    end

    test "does not warn when the timeout accommodates a cross-device ceremony" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(
            strategy_options: """
            hints [:hybrid, :security_key]
            timeout 300_000
            """
          )
        end)

      refute output =~ ":hybrid"
    end
  end

  # The sign-in challenge never lists credentials, so sign-in needs a
  # discoverable credential whether or not the strategy requires an identity.
  describe "resident_key" do
    for resident_key <- [:preferred, :discouraged] do
      test "warns that #{inspect(resident_key)} can create a passkey no one can sign in with" do
        output =
          capture_io(:stderr, fn ->
            compile_pair(strategy_options: "resident_key #{inspect(unquote(resident_key))}")
          end)

        assert output =~ "signs users in with `resident_key #{inspect(unquote(resident_key))}`"
      end
    end

    test "warns in identity mode too" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(
            identity_options: """
            identity_field :email
            require_identity? true
            """,
            user_attributes: "attribute :email, :ci_string, allow_nil?: false, public?: true",
            user_body: """
            actions do
              defaults [:read]
            end

            identities do
              identity :unique_email, [:email],
                pre_check_with: AshAuthentication.Test.PermissiveDomain
            end
            """,
            strategy_options: "resident_key :preferred"
          )
        end)

      assert output =~ "signs users in with `resident_key :preferred`"
      # The identity-mode resource is otherwise valid: the warning is all.
      refute output =~ "DslError"
    end

    test "does not warn for :required" do
      output =
        capture_io(:stderr, fn -> compile_pair(strategy_options: "resident_key :required") end)

      refute output =~ "resident_key"
    end

    test "does not warn when the strategy doesn't sign anyone in" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(
            strategy_options: """
            resident_key :discouraged
            sign_in_enabled? false
            """
          )
        end)

      refute output =~ "resident_key"
    end
  end

  describe "manages_credentials_relationship?/2" do
    test "true when a change manages the given relationship" do
      action = %{
        changes: [
          %{
            change:
              {Ash.Resource.Change.ManageRelationship,
               argument: :webauthn_credentials, relationship: :webauthn_credentials, opts: []}
          }
        ]
      }

      assert Verifier.manages_credentials_relationship?(action, :webauthn_credentials)
    end

    test "false when no change manages the given relationship" do
      action = %{
        changes: [
          %{change: AshAuthentication.GenerateTokenChange}
        ]
      }

      refute Verifier.manages_credentials_relationship?(action, :webauthn_credentials)
    end

    test "false when a change manages a different relationship" do
      action = %{
        changes: [
          %{
            change:
              {Ash.Resource.Change.ManageRelationship,
               argument: :some_other_relationship,
               relationship: :some_other_relationship,
               opts: []}
          }
        ]
      }

      refute Verifier.manages_credentials_relationship?(action, :webauthn_credentials)
    end
  end

  # Compiles a throwaway credential resource, then a throwaway user resource
  # carrying a `webauthn` strategy that points at it.
  #
  # The two are compiled in separate passes, in that order, for two reasons
  # that pull against each other: the credential's transformer reads the user
  # resource's primary key, so it needs *a* compiled user resource (hence the
  # already-compiled `Example.UserWithWebAuthn` stand-in as its
  # `user_resource`); and the strategy verifier skips every credential check
  # when the credential module isn't loaded yet, so it has to be compiled
  # first for these tests to exercise anything at all.
  #
  # Strategy verifier failures run from `@after_verify`, so the parallel
  # checker reports them on stderr rather than raising out of
  # `Code.compile_string/1` — hence `capture_io(:stderr, ...)` at the call
  # sites instead of `assert_raise`.
  defp compile_pair(opts) do
    suffix = System.unique_integer([:positive])
    user_module = "AshAuthentication.Strategy.WebAuthn.VerifierTest.User#{suffix}"
    credential_module = "AshAuthentication.Strategy.WebAuthn.VerifierTest.Credential#{suffix}"

    # Defaults describe a *valid* pair, so each test overrides only the one
    # thing it is about. `:user#{suffix}` matches the foreign key Ash derives
    # for the generated `has_many` from the user resource's own name.
    extensions =
      Keyword.get(
        opts,
        :credential_extensions,
        ",\n    extensions: [AshAuthentication.WebAuthnCredential]"
      )

    relationship_name = Keyword.get(opts, :user_relationship_name, ":user#{suffix}")

    body =
      Keyword.get(opts, :credential_body, """
        webauthn_credential do
          user_resource Example.UserWithWebAuthn
          user_relationship_name #{relationship_name}
        end
      """)

    Code.compile_string("""
    defmodule #{credential_module} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets#{extensions}

      ets do
        private?(true)
      end

    #{body}
    end
    """)

    @user_source
    |> String.replace("<%= user_module %>", user_module)
    |> String.replace("<%= credential_module %>", credential_module)
    |> String.replace("<%= strategy_options %>", Keyword.get(opts, :strategy_options, ""))
    |> String.replace(
      "<%= origin %>",
      Keyword.get(opts, :origin, ~s(origin "https://example.com"))
    )
    |> String.replace(
      "<%= identity_options %>",
      Keyword.get(opts, :identity_options, "require_identity? false")
    )
    |> String.replace("<%= user_attributes %>", Keyword.get(opts, :user_attributes, ""))
    |> String.replace("<%= user_body %>", Keyword.get(opts, :user_body, ""))
    |> Code.compile_string()
  end
end
