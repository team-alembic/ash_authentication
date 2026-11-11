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
            "The ceremony backend adapter — handles challenge generation, verification, and challenge (de)serialization, and brings its own dependencies: the default needs the optional `wax_` package, a custom adapter does not. See `AshAuthentication.Strategy.WebAuthn.Adapter`.",
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

          The Secret's context carries the tenant under `:tenant`, the
          `Plug.Conn` under `:conn` when resolved in a plug, and the Ash
          context the plug or action was given, so it can resolve per tenant
          or per request too:

              def secret_for([:authentication, :strategies, :webauthn, :rp_id], _resource, _opts, %{
                    tenant: tenant
                  }),
                  do: {:ok, rp_id_for(tenant)}

          Tenants on subdomains of one domain may share that domain as their
          `rp_id` and differ in `origin`, which is exact.
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
          implementing `AshAuthentication.Secret`, which receives the same
          context as for `rp_id`:

              rp_name MyApp.Secrets
          """,
          required: true
        ],
        origin: [
          type:
            {:or,
             [
               :string,
               {:list, :string},
               {:mfa_or_fun, 1},
               {:spark_function_behaviour, AshAuthentication.Secret,
                {AshAuthentication.SecretFunction, 2}}
             ]},
          doc: """
          The origins WebAuthn ceremonies are accepted from — an allowlist.

          In WebAuthn, the **origin** is the scheme + host + port the browser
          reports (and signs) during registration and authentication. It is distinct
          from `rp_id`:

          - `rp_id` = domain only (e.g. `"example.com"`)
          - `origin` = full URL (e.g. `"https://example.com"` or `"https://localhost:4001"`)

          **When set**, the browser's origin must match one of the configured origins
          exactly, port included. The request that minted the challenge plays no part,
          so this works unchanged behind a TLS-terminating proxy.

          **When not set** (the default), an origin is accepted when its scheme is
          `https` and its host is the `rp_id` or a subdomain of it, on any port —
          which is exactly the set of origins a browser lets use that RP ID.
          `http://localhost[:port]` is accepted too when `rp_id` is `"localhost"`.
          Most deployments, including development on a non-standard port, need no
          `origin` at all; set it to narrow the policy to specific hosts or ports.

          **One origin:**

              origin "https://app.example.com"

          **Several:**

              origin ["https://app.example.com", "https://admin.example.com"]

          **Dynamic (multi-tenant)** — a 1-arity function or MFA of the tenant
          returning a string or list:

              origin {MyApp.WebAuthn, :origins_for_tenant, []}

          **Per environment** (what the generator sets up) — an
          `AshAuthentication.Secret` reading the application environment and
          returning `{:ok, origin}` or `{:ok, [origin, ...]}`:

              origin MyApp.Secrets

          The Secret's context carries the tenant under `:tenant`, the
          `Plug.Conn` under `:conn` when resolved in a plug, and the Ash
          context the plug or action was given, so a Secret can also answer
          per tenant: tenants on subdomains of a shared `rp_id` each return
          their own exact origin(s) here:

              def secret_for([:authentication, :strategies, :webauthn, :origin], _resource, _opts, %{
                    tenant: tenant
                  }),
                  do: {:ok, "https://\#{tenant}.example.com"}

          A dynamic value that comes back `nil`, `""` or `[]` (or a Secret
          answering `:error`) counts as not set, so an environment that leaves
          `:webauthn_origin` out of its config gets the default policy. See
          "Relying party and origin" in the WebAuthn guide.
          """,
          required: false
        ],
        identity_field: [
          type: :atom,
          doc:
            "The name of the attribute which uniquely identifies the user (e.g. `:email`). Used for looking up the user during authentication. When `require_identity?` is `false` the user resource needn't have it.",
          default: :email
        ],
        require_identity?: [
          type: :boolean,
          default: true,
          doc: """
          Defaults to `true` (identity-required mode). Set to `false` for
          passkey-only mode.

          When `true` (identity-required mode), the user resource must expose an
          `identity_field` attribute (default `:email`) that is writable, public,
          and uniquely constrained. Registration stores the identity. Sign-in
          uses a discoverable credential, as in passkey-first mode (the
          challenge endpoint is public, so it never lists a user's
          credentials); an identity submitted with the sign-in must match the
          credential's owner.

          When `false` (passkey-first mode), the user resource needs no identity
          column, and the register and sign-in actions take none. Users sign in
          via a discoverable credential only; the credential id resolves the
          user at verification time.
          """
        ],
        authenticator_attachment: [
          type: {:in, [nil, :platform, :cross_platform]},
          doc:
            "Restricts authenticator type. `nil` allows any, `:platform` limits to built-in (Touch ID, Windows Hello), `:cross_platform` limits to USB/NFC keys (YubiKey).",
          default: nil
        ],
        hints: [
          type: {:list, {:in, [:security_key, :client_device, :hybrid]}},
          doc: """
          Which kinds of authenticator the browser should offer, in order of
          preference (the WebAuthn Level 3 `hints` member).

          * `:hybrid` -- another device, reached by scanning a QR code with a
            phone or tablet ("use your phone or tablet").
          * `:security_key` -- a removable USB/NFC key.
          * `:client_device` -- the authenticator built in to this device
            (Touch ID, Windows Hello).

          `hints [:hybrid, :security_key]` produces the two-option cross-device
          dialog. This is a presentation hint only -- it changes which options
          the browser leads with and never relaxes verification. Clients which
          do not implement `hints` (currently everything but Chromium >= 128)
          ignore it and fall back to their default picker.

          Cross-device ceremonies involve a QR scan, a Bluetooth handshake and a
          prompt on the second device, so raise `timeout` to at least `120_000`
          when `:hybrid` is offered.
          """,
          default: []
        ],
        allow_hint_override?: [
          type: :boolean,
          doc: """
          Whether a `hints` request parameter on the challenge endpoints
          overrides the configured `hints`.

          Lets a UI offer separate entry points ("sign in with a phone", "use a
          security key") which jump straight to one kind of authenticator, by
          requesting e.g. `?hints=hybrid`. Values outside the `hints` enum are
          discarded, and a request which names none of them falls back to the
          configured value.

          The parameter only affects the dialog the requesting browser shows
          itself; every security-relevant option stays server-derived.
          """,
          default: false
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
            "Attestation conveyance preference. `\"none\"` is recommended for most use cases. `\"indirect\"` allows the client to substitute an anonymized attestation, `\"direct\"` requests the authenticator's attestation statement verbatim, and `\"enterprise\"` requests individually-identifying attestation (requires browser/authenticator support and policy). Verifying attestation beyond `:none`/`:self` types requires FIDO metadata — see the WebAuthn guide. NOTE: requesting `\"direct\"` only asks the client to *convey* an attestation statement; it does not verify it. A client may answer any preference with a `\"none\"` statement (synced passkeys always do); whatever it conveys is verified as such and accepted or refused by `trusted_attestation_types`. Under `\"none\"`, a statement the client sends anyway is discarded, as the client itself should have done. With the default `trusted_attestation_types` (which accept `:none`/`:uncertain`) and `verify_trust_root?` set to `false`, the statement is not checked against any trust root. To actually enforce attestation you must tighten `trusted_attestation_types`, set `verify_trust_root?` to `true`, and give the adapter FIDO metadata (for the default adapter, configure the `:wax_` application).",
          default: "none"
        ],
        trusted_attestation_types: [
          type: {:list, {:in, [:none, :basic, :self, :attca, :anonca, :uncertain]}},
          doc:
            "The attestation types accepted at registration, as the adapter classifies the verified statement: `:none` (no statement), `:self` (signed with the credential's own key), `:basic`, `:attca` and `:anonca` (chaining to a known root), or `:uncertain` (a chain the adapter has no metadata to judge). Restrict to e.g. `[:basic, :attca]` to only accept authenticators whose attestation chains to a known root — this requires FIDO metadata (for the default adapter, configured on the `:wax_` application).",
          default: [:none, :basic, :self, :uncertain]
        ],
        verify_trust_root?: [
          type: :boolean,
          doc:
            "Whether to verify the attestation trust root for `packed` and `u2f` attestation formats (`tpm` is always checked against metadata). Requires FIDO metadata (for the default adapter, configured on the `:wax_` application).",
          default: false
        ],
        timeout: [
          type: :pos_integer,
          doc:
            "Timeout for WebAuthn ceremonies in milliseconds. Sent to the browser, and enforced on the server: a challenge answered after it has elapsed (rounded up to whole seconds) is rejected. Cross-device (`:hybrid`) ceremonies need considerably longer than a local one -- at least `120_000`.",
          default: 60_000
        ],
        resident_key: [
          type: {:in, [:required, :preferred, :discouraged]},
          doc:
            "Whether registration asks for a discoverable credential (a passkey stored on the authenticator, which can be offered without the server naming it) or allows a non-discoverable one (which the authenticator can only use when the server sends its id back). Sign-in only ever uses discoverable credentials (the public challenge endpoint never lists a user's credentials), so keep `:required` for any strategy that signs users in; the strategy warns at compile time otherwise. `:preferred` may still yield a non-discoverable credential (e.g. on a security key whose storage is full), and `:discouraged` usually does; both are only safe with `sign_in_enabled? false`. See \"Discoverable and non-discoverable credentials\" in the WebAuthn guide.",
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
            tripping the check. The credential record is left untouched for that
            assertion, so `last_used_at` and `backed_up` aren't refreshed either.
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
            "Whether the strategy can sign users in directly (i.e. WebAuthn is the primary credential). Set to `false` when using WebAuthn purely as a second factor. The `sign_in_with_token` exchange stays while `verify_enabled?` is on, since `verify` answers with a sign-in token too.",
          default: true
        ],
        verify_enabled?: [
          type: :boolean,
          doc:
            "Whether the strategy exposes a `:verify` phase that proves possession of a passkey for an already-authenticated user. Used for second-factor and step-up flows.",
          default: true
        ],
        add_credential_enabled?: [
          type: :boolean,
          doc: """
          Whether an authenticated user can add another passkey to their
          account (the `add_credential_challenge` and `add_credential` phases).
          Turn it off when passkeys are enrolled only at registration, or only
          through your own flow.
          """,
          default: true
        ],
        add_credential_max_authentication_age: [
          type:
            {:or,
             [
               nil,
               :pos_integer,
               {:tuple, [:pos_integer, {:in, [:days, :hours, :minutes, :seconds]}]}
             ]},
          doc: """
          When set, adding a passkey requires the user to have authenticated
          within this long (seconds, or e.g. `{5, :minutes}`); otherwise both
          `add_credential` phases fail, and the UI should ask the user to sign
          in again or complete a second-factor verification first.

          A new passkey is a lasting way into the account, so this stops a
          stolen or long-lived session from being used to plant one. What
          counts as authenticating: signing in (the session token's issue
          time), a second-factor verification (`webauthn_verified_at`,
          `totp_verified_at`), or a time the caller passes explicitly. See
          `AshAuthentication.Strategy.WebAuthn.RecentAuthentication`.

          Defaults to `nil`: any authenticated user may add a passkey.
          """,
          default: nil
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
            "The name of the action used to sign in with a short-lived token issued by a successful WebAuthn `sign_in` or `verify`. Built while either of them is enabled. Defaults to `sign_in_with_<strategy_name>_token`.",
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
