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
        end
        """
      ],
      args: [{:optional, :name, :webauthn}],
      hide: [:name],
      target: WebAuthn,
      no_depend_modules: [:credential_resource],
      schema: [
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
               {:mfa_or_fun, 1}
             ]},
          doc: """
          Relying Party ID - your domain name (e.g. "example.com").

          For multi-tenant setups, pass an MFA tuple or 1-arity function that
          receives the tenant and returns the domain string:

              rp_id {MyApp.WebAuthn, :rp_id_for_tenant, []}
          """,
          required: true
        ],
        rp_name: [
          type:
            {:or,
             [
               :string,
               {:mfa_or_fun, 1}
             ]},
          doc: """
          Relying Party display name shown to the user during registration.

          For multi-tenant setups, pass an MFA tuple or 1-arity function:

              rp_name {MyApp.WebAuthn, :rp_name_for_tenant, []}
          """,
          required: true
        ],
        origin: [
          type:
            {:or,
             [
               :string,
               {:mfa_or_fun, 1}
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
          """,
          required: false
        ],
        identity_field: [
          type: :atom,
          doc:
            "The name of the attribute which uniquely identifies the user (e.g. `:email`). Used for looking up the user during authentication.",
          default: :email
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
          type: {:in, ["none", "direct"]},
          doc:
            "Attestation conveyance preference. `\"none\"` is recommended for most use cases. `\"direct\"` requests the authenticator's attestation certificate.",
          default: "none"
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
        credential_id_field: [
          type: :atom,
          doc: "The name of the credential ID attribute on the credential resource.",
          default: :credential_id
        ],
        public_key_field: [
          type: :atom,
          doc: "The name of the public key attribute on the credential resource.",
          default: :public_key
        ],
        sign_count_field: [
          type: :atom,
          doc: "The name of the sign count attribute on the credential resource.",
          default: :sign_count
        ],
        label_field: [
          type: :atom,
          doc: "The name of the label attribute on the credential resource.",
          default: :label
        ],
        last_used_at_field: [
          type: :atom,
          doc:
            "The name of the last_used_at attribute on the credential resource. Set to `nil` to disable tracking.",
          default: :last_used_at
        ],
        user_relationship_name: [
          type: :atom,
          doc:
            "The name of the belongs_to relationship on the credential resource pointing to the user.",
          default: :user
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
        register_action_name: [
          type: :atom,
          doc:
            "The name of the register action on the user resource. Defaults to `register_with_<strategy_name>`.",
          required: false
        ],
        sign_in_action_name: [
          type: :atom,
          doc:
            "The name of the sign-in action on the user resource. Defaults to `sign_in_with_<strategy_name>`.",
          required: false
        ],
        store_credential_action_name: [
          type: :atom,
          doc:
            "The name of the create action on the credential resource. Defaults to `store_<strategy_name>_credential`.",
          required: false
        ],
        update_sign_count_action_name: [
          type: :atom,
          doc:
            "The name of the update action for sign_count on the credential resource. Defaults to `update_<strategy_name>_sign_count`.",
          required: false
        ],
        list_credentials_action_name: [
          type: :atom,
          doc:
            "The name of the read action to list credentials. Defaults to `list_<strategy_name>_credentials`.",
          required: false
        ],
        delete_credential_action_name: [
          type: :atom,
          doc:
            "The name of the destroy action for credentials. Defaults to `delete_<strategy_name>_credential`.",
          required: false
        ],
        update_credential_label_action_name: [
          type: :atom,
          doc:
            "The name of the update action for credential labels. Defaults to `update_<strategy_name>_credential_label`.",
          required: false
        ],
        add_credential_action_name: [
          type: :atom,
          doc:
            "The name of the action to add a credential to an existing user. Defaults to `add_<strategy_name>_credential`.",
          required: false
        ]
      ]
    }
  end
end
