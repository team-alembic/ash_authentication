# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Dsl do
  @moduledoc """
  Defines the Spark DSL entity for the WebAuthn strategy.
  """

  alias AshAuthentication.Strategy.WebAuthn
  alias Spark.Dsl.Entity

  @doc false
  @spec dsl :: map
  def dsl do
    %Entity{
      name: :webauthn,
      describe: """
      Strategy for authenticating using WebAuthn/FIDO2 hardware security keys and passkeys.
      """,
      examples: [
        """
        webauthn :webauthn do
          credential_resource MyApp.Accounts.Credential
          rp_id "example.com"
          rp_name "My App"
          identity_field :email
          require_identity? true
        end
        """
      ],
      args: [{:optional, :name, :webauthn}],
      hide: [:name],
      target: WebAuthn,
      no_depend_modules: [:credential_resource, :adapter],
      schema: [
        adapter: [
          type: {:behaviour, AshAuthentication.Strategy.WebAuthn.Adapter},
          doc:
            "The ceremony backend adapter — handles challenge generation, verification, and challenge (de)serialization. See `AshAuthentication.Strategy.WebAuthn.Adapter`.",
          default: AshAuthentication.Strategy.WebAuthn.Adapters.Wax
        ],
        name: [
          type: :atom,
          doc: "Uniquely identifies the strategy.",
          required: true
        ],
        credential_resource: [
          type: {:or, [:atom, {:behaviour, Ash.Resource}]},
          doc:
            "The Ash resource used to store WebAuthn credentials. Must have `credential_id` (binary), `public_key` (binary), and `sign_count` (integer) attributes, plus a `belongs_to` relationship to the user resource.",
          required: true
        ],
        rp_id: [
          type:
            {:or,
             [
               :string,
               {:mfa_or_fun, 1},
               {:spark_function_behaviour, AshAuthentication.Secret,
                {AshAuthentication.SecretFunction, 2}}
             ]},
          doc: """
          Relying Party ID - your domain name (e.g. "example.com").

          For multi-tenant setups, pass an MFA tuple or 1-arity function that
          receives the tenant and returns the domain string:

              rp_id {MyApp.WebAuthn, :rp_id_for_tenant, []}

          For application-environment-driven configuration, point at a module
          implementing `AshAuthentication.Secret`:

              rp_id MyApp.Secrets
          """,
          required: true
        ],
        rp_name: [
          type:
            {:or,
             [
               :string,
               {:mfa_or_fun, 1},
               {:spark_function_behaviour, AshAuthentication.Secret,
                {AshAuthentication.SecretFunction, 2}}
             ]},
          doc: """
          Relying Party display name shown to the user during registration.

          For multi-tenant setups, pass an MFA tuple or 1-arity function:

              rp_name {MyApp.WebAuthn, :rp_name_for_tenant, []}

          For application-environment-driven configuration, point at a module
          implementing `AshAuthentication.Secret`:

              rp_name MyApp.Secrets
          """,
          required: true
        ],
        origin: [
          type:
            {:or,
             [
               :string,
               {:mfa_or_fun, 1},
               {:spark_function_behaviour, AshAuthentication.Secret,
                {AshAuthentication.SecretFunction, 2}}
             ]},
          doc: """
          The expected origin for WebAuthn ceremonies.

          In WebAuthn, the **origin** is the scheme + domain + port that the browser
          reports during registration and authentication. It is distinct from `rp_id`:

          - `rp_id` = domain only (e.g. `"example.com"`)
          - `origin` = full URL (e.g. `"https://example.com"` or `"https://localhost:4001"`)

          If not set, defaults to `"https://{rp_id}"`. This default **omits the port**,
          which works for production on port 443 but will cause Wax to reject ceremonies
          in development where the port is non-standard.

          **Production:**

              origin "https://example.com"

          **Development (non-standard port):**

              origin "https://localhost:4001"

          **Dynamic (multi-tenant):**

              origin {MyApp.WebAuthn, :origin_for_tenant, []}

          **Application-environment-driven:**

              origin MyApp.Secrets
          """,
          required: false
        ],
        identity_field: [
          type: :atom,
          doc:
            "The name of the attribute which uniquely identifies the user (e.g. `:email`). Used for looking up the user during authentication. Ignored when `require_identity?` is `false`.",
          default: :email
        ],
        require_identity?: [
          type: :boolean,
          required: true,
          doc: """
          Must be set explicitly. There is no default; the developer chooses the mode per resource.

          When `true` (identity-required mode), the user resource must expose an
          `identity_field` attribute (default `:email`) that is writable, public,
          and uniquely constrained. Users sign in by supplying this identity at
          challenge time; their credentials are returned via `allowCredentials`.

          When `false` (passkey-first mode), the user resource needs no identity
          column. Users sign in via a discoverable credential only; the
          credential id resolves the user at verification time. Pairs with
          `resident_key: :required`.

          Note: the runtime in `Actions.sign_in/3` and `Plug.authentication_challenge/2`
          supports both modes; this option only relaxes the compile-time checks
          in the transformer and the sign-in preparation.
          """
        ],
        authenticator_attachment: [
          type: {:in, [nil, :platform, :cross_platform]},
          doc:
            "Restricts authenticator type. `nil` allows any, `:platform` limits to built-in (Touch ID, Windows Hello), `:cross_platform` limits to USB/NFC keys (YubiKey).",
          default: nil
        ],
        user_verification: [
          type: {:in, ["required", "preferred", "discouraged"]},
          doc:
            "Whether user verification (PIN/biometric) is required. Use `\"required\"` for highest security.",
          default: "preferred"
        ],
        attestation: [
          type: {:in, ["none", "indirect", "direct", "enterprise"]},
          doc:
            "Attestation conveyance preference. `\"none\"` is recommended for most use cases. `\"indirect\"` allows the client to substitute an anonymized attestation, `\"direct\"` requests the authenticator's attestation statement verbatim, and `\"enterprise\"` requests individually-identifying attestation (requires browser/authenticator support and policy). Verifying attestation beyond `:none`/`:self` types requires FIDO metadata — see the WebAuthn guide.",
          default: "none"
        ],
        trusted_attestation_types: [
          type: {:list, {:in, [:none, :basic, :self, :attca, :anonca, :uncertain]}},
          doc:
            "The attestation types accepted at registration (see `t:Wax.Attestation.type/0`). Restrict to e.g. `[:basic, :attca]` to only accept authenticators whose attestation chains to a known root — this requires FIDO metadata to be configured for the `:wax_` application.",
          default: [:none, :basic, :self, :uncertain]
        ],
        verify_trust_root?: [
          type: :boolean,
          doc:
            "Whether to verify the attestation trust root for `packed` and `u2f` attestation formats (`tpm` is always checked against metadata). Requires FIDO metadata to be configured for the `:wax_` application.",
          default: false
        ],
        timeout: [
          type: :pos_integer,
          doc: "Timeout for WebAuthn ceremonies in milliseconds.",
          default: 60_000
        ],
        resident_key: [
          type: {:in, [:required, :preferred, :discouraged]},
          doc:
            "Whether to require discoverable credentials (passkeys). `:required` enables username-less authentication.",
          default: :required
        ],
        sign_count_policy: [
          type: {:in, [:reject, :log, :ignore]},
          doc: """
          How to react when an assertion's sign count has not increased over the
          stored value — the WebAuthn signal that the authenticator may have been
          cloned (§6.1.1).

          The check only fires when the authenticator actually implements a
          counter: synced passkeys report a constant `0` on both sides and are
          never flagged.

          - `:reject` (default) — fail the ceremony with an authentication error.
          - `:log` — allow the ceremony but log a warning; the stored sign count
            is deliberately **not** lowered, so a cloned authenticator keeps
            tripping the check.
          - `:ignore` — no check; the stored count is simply overwritten.
          """,
          default: :reject
        ],
        credentials_relationship_name: [
          type: :atom,
          doc:
            "The name of the has_many relationship on the user resource pointing to credentials.",
          default: :webauthn_credentials
        ],
        registration_enabled?: [
          type: :boolean,
          doc: "Whether to allow new user registration via WebAuthn.",
          default: true
        ],
        sign_in_enabled?: [
          type: :boolean,
          doc:
            "Whether the strategy can sign users in directly (i.e. WebAuthn is the primary credential). Set to `false` when using WebAuthn purely as a second factor.",
          default: true
        ],
        verify_enabled?: [
          type: :boolean,
          doc:
            "Whether the strategy exposes a `:verify` phase that proves possession of a passkey for an already-authenticated user. Used for second-factor and step-up flows.",
          default: true
        ],
        register_action_name: [
          type: :atom,
          doc:
            "The name of the register action on the user resource. Defaults to `register_with_<strategy_name>`.",
          required: false
        ],
        register_action_accept: [
          type:
            {:list,
             {:or, [:atom, {:tuple, [:atom, {:keyword_list, [secret?: [type: :boolean]]}]}]}},
          default: [],
          doc:
            "A list of additional writable attributes to be accepted in the register action (e.g. `[:name]`). Their values are validated by the action as usual, so `allow_nil?`, constraints, and any validations on the resource apply. Attributes marked `sensitive?: true` must confirm whether they are secrets via a `{field, secret?: boolean}` entry (e.g. `[given_names: [secret?: false]]`); `secret?: true` renders a masked input, `secret?: false` a regular one.",
          required: false
        ],
        sign_in_action_name: [
          type: :atom,
          doc:
            "The name of the sign-in action on the user resource. Defaults to `sign_in_with_<strategy_name>`.",
          required: false
        ],
        sign_in_with_token_action_name: [
          type: :atom,
          doc:
            "The name of the action used to sign in with a short-lived token issued by a successful WebAuthn ceremony. Defaults to `sign_in_with_<strategy_name>_token`.",
          required: false
        ],
        verify_action_name: [
          type: :atom,
          doc:
            "The name of the second-factor verify action on the user resource. Defaults to `verify_<strategy_name>`.",
          required: false
        ]
      ]
    }
  end
end
