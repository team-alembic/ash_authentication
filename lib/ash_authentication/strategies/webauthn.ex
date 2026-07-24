# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authenticating using [WebAuthn/FIDO2](https://webauthn.io/) hardware
  security keys and passkeys.

  This strategy supports:

  - Hardware security keys (YubiKey, etc.)
  - Platform authenticators (Touch ID, Windows Hello, Face ID)
  - Discoverable credentials / passkeys
  - Multi-tenancy (dynamic `rp_id` per tenant)

  Credentials are stored in a separate Ash resource that you define. The strategy
  auto-generates actions on both the user resource and the credential resource for
  registration, sign-in, credential management, and challenge generation.

  ## Modes

  The strategy can be configured for two roles via the `registration_enabled?`,
  `sign_in_enabled?`, and `verify_enabled?` flags:

  - **Primary** (default; all three flags `true`) — passkeys are the primary
    credential. Users register and sign in directly with their authenticator.
  - **Second factor** (`registration_enabled? false`, `sign_in_enabled? false`,
    `verify_enabled? true`) — passkeys are only used as a second factor on top
    of another primary credential (e.g. password). The strategy doesn't
    register or sign in users directly; it only verifies an assertion against
    the *currently authenticated* user. On successful verification, a
    `webauthn_verified_at` claim is added to the user's authentication token
    so protected routes can require it.

  See the
  [Passkeys as 2FA](https://hexdocs.pm/ash_authentication_phoenix/webauthn-2fa.html)
  guide for the second-factor flow end to end.

  ## Quick Start

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false
    end

    authentication do
      tokens do
        enabled? true
        token_resource MyApp.Accounts.Token
        signing_secret fn _, _ -> {:ok, Application.get_env(:my_app, :token_secret)} end
      end

      strategies do
        webauthn :webauthn do
          credential_resource MyApp.Accounts.Credential
          rp_id "example.com"
          rp_name "My App"
          origin "https://example.com"
          identity_field :email
          require_identity? true
        end
      end
    end

    identities do
      identity :unique_email, [:email]
    end
  end
  ```

  ## Origin Configuration

  The **origin** is the full URL the browser sends during WebAuthn ceremonies
  (scheme + domain + port). The **rp_id** is the domain name only. These are
  related but distinct:

  | Setting   | Example                    | What it is                       |
  |-----------|----------------------------|----------------------------------|
  | `rp_id`   | `"example.com"`            | Domain only (Relying Party ID)   |
  | `origin`  | `"https://example.com"`    | Full URL including scheme + port |

  If `origin` is not set, it defaults to `"https://{rp_id}"`. This works for
  production on standard port 443, but **breaks in development** because the
  browser includes the port in the origin and `Wax` will reject the mismatch.

  ### Production

      origin "https://example.com"

  ### Development (non-standard port)

      origin "https://localhost:4001"

  ### Multi-tenant (dynamic per tenant)

      origin {MyApp.WebAuthn, :origin_for_tenant, []}

  ## Credential Resource

  You must define a separate Ash resource to store WebAuthn credentials. Add the
  `AshAuthentication.WebAuthnCredential` extension and it will automatically scaffold
  the required attributes (`credential_id`, `public_key`, `sign_count`, `label`,
  `last_used_at`), the `belongs_to` relationship back to the user resource, the
  unique identity on `credential_id`, and all four CRUD actions. The matching
  `has_many :webauthn_credentials` relationship on the user resource is scaffolded
  by the `webauthn` strategy itself. Either relationship can still be declared by
  hand if you need non-default options — whatever you don't declare is built for you.

  ```elixir
  defmodule MyApp.Accounts.Credential do
    use Ash.Resource,
      domain: MyApp.Accounts,
      data_layer: AshPostgres.DataLayer,
      authorizers: [Ash.Policy.Authorizer],
      extensions: [AshAuthentication.WebAuthnCredential]

    webauthn_credential do
      user_resource MyApp.Accounts.User
    end

    postgres do
      table "webauthn_credentials"
      repo(MyApp.Repo)
    end

    policies do
      bypass AshAuthentication.Checks.AshAuthenticationInteraction do
        authorize_if always()
      end

      policy always() do
        authorize_if always()
      end
    end

    attributes do
      uuid_primary_key :id
      create_timestamp :inserted_at
      update_timestamp :updated_at
    end
  end
  ```

  ## Token Configuration

  Tokens **must** be enabled for WebAuthn to work. The `signing_secret` callback
  must return an `{:ok, value}` tuple, not a raw string:

  ```elixir
  authentication do
    tokens do
      enabled? true
      token_resource MyApp.Accounts.Token
      signing_secret fn _, _ -> {:ok, Application.get_env(:my_app, :token_secret)} end
    end
  end
  ```

  ## Adding Credentials to Existing Users

  The built-in `register` action creates a **new user** with a credential. To add
  a passkey to an already-authenticated user, you need a custom controller that:

  1. Generates a registration challenge (via `Wax.new_registration_challenge/1`)
  2. Sends it to the browser
  3. Receives the attestation response
  4. Calls `Wax.register/3` to verify it
  5. Stores the credential directly on the credential resource

  This is intentional -- the strategy's register flow is for new user sign-up,
  not for adding keys to existing accounts.

  ## Accessing the User After Authentication

  After successful WebAuthn sign-in, the JWT is available in user metadata:

  ```elixir
  token = user.__metadata__[:token]
  ```

  To load a user from a token (e.g., in a LiveView `mount`):

  ```elixir
  {:ok, user} = AshAuthentication.subject_to_user(
    "user?id=\#{user_id}",
    MyApp.Accounts.User
  )
  ```

  ## Multi-Tenancy

  For multi-tenant applications, `rp_id`, `rp_name`, and `origin` all accept
  MFA tuples that receive the tenant as the first argument:

  ```elixir
  webauthn :webauthn do
    credential_resource MyApp.Accounts.Credential
    rp_id {MyApp.WebAuthn, :rp_id_for_tenant, []}
    rp_name {MyApp.WebAuthn, :rp_name_for_tenant, []}
    origin {MyApp.WebAuthn, :origin_for_tenant, []}
    identity_field :email
    require_identity? true
  end
  ```

  Then implement the callbacks:

  ```elixir
  defmodule MyApp.WebAuthn do
    def rp_id_for_tenant(tenant), do: "\#{tenant}.example.com"
    def rp_name_for_tenant(tenant), do: "MyApp - \#{tenant}"
    def origin_for_tenant(tenant), do: "https://\#{tenant}.example.com"
  end
  ```

  ## Passkey-First (No Identity) Flow

  By default the strategy requires an `identity_field` attribute (e.g. `:email`)
  on the user resource. For passkey-only systems — internal admin apps, or apps
  where the user resource has no email-style column at all — set
  `require_identity? false` and the requirement is lifted entirely:

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    attributes do
      uuid_primary_key :id
    end

    authentication do
      tokens do
        enabled? true
        token_resource MyApp.Accounts.Token
        signing_secret fn _, _ -> {:ok, Application.get_env(:my_app, :token_secret)} end
      end

      strategies do
        webauthn :webauthn do
          credential_resource MyApp.Accounts.Credential
          rp_id "example.com"
          rp_name "My App"
          origin "https://example.com"
          require_identity? false
        end
      end
    end
  end
  ```

  No `:email` attribute, no unique identity. At challenge time no identity is
  sent to the server, so the browser surfaces a discoverable credential
  (passkey); at verification time the credential id alone resolves the user.

  This composes with `resident_key: :required` (the default): `resident_key`
  controls whether the browser is asked to create a discoverable credential
  during registration, while `require_identity?` controls whether the
  user resource must expose an identity column. Set both for the full
  passkey-first experience.

  The companion package `ash_authentication_phoenix` needs to skip the email
  input in its sign-in components for this mode — see its documentation.

  **Gotcha:** registration creates a user with no identity, so this mode is
  unsuitable when paired with strategies that need an email on the same
  resource (e.g. password with resettable, magic link, or confirmation).

  ## Gotchas

  - **Origin must include the port** for non-standard ports (e.g., `"https://localhost:4001"`).
    The default derivation from `rp_id` produces `"https://{rp_id}"` which omits the port.
  - **Signing secret must return `{:ok, value}`**, not a raw string. A common mistake
    is `fn _, _ -> "my_secret" end` -- it must be `fn _, _ -> {:ok, "my_secret"} end`.
  - **Challenge data is stored in the session as plain maps**, not `Wax.Challenge` structs,
    because cookie session stores cannot serialize arbitrary Elixir structs. The plug
    reconstructs the struct before passing it to Wax.
  - **`add_credential` (adding a key to an existing user) is not built-in.** The `register`
    action creates a new user. See "Adding Credentials to Existing Users" above.
  - **`origin_verify_fun`** is hardcoded to `{Wax, :origins_match?, []}` when
    reconstructing challenges from the session. If you need custom origin verification,
    you'll need to override the plug.
  - **Token generation happens in `Actions.sign_in`** via `Jwt.token_for_user/3`, not in
    an Ash preparation like the Password strategy. This is because Wax verification
    happens outside the Ash action pipeline.

  ## Credential resource configuration

  Since 5.0 the credential resource must use the
  `AshAuthentication.WebAuthnCredential` extension. The names of its
  attributes, and of its `belongs_to` to the user resource, are declared once
  on its own `webauthn_credential` section -- not on this strategy. The
  accessors in this module read them back off `credential_resource`, so they
  always reflect what that resource actually declares:

      strategy = AshAuthentication.Info.strategy!(MyApp.Accounts.User, :webauthn)
      AshAuthentication.Strategy.WebAuthn.credential_id_field(strategy)
      #=> :credential_id

  If you have the credential resource module rather than the strategy, call
  `AshAuthentication.WebAuthnCredential.Info` directly instead.
  """

  @struct_fields [
    name: nil,
    provider: :webauthn,
    adapter: AshAuthentication.Strategy.WebAuthn.Adapters.Wax,
    resource: nil,
    credential_resource: nil,
    rp_id: nil,
    rp_name: nil,
    origin: nil,
    identity_field: :email,
    require_identity?: nil,
    authenticator_attachment: nil,
    user_verification: "preferred",
    attestation: "none",
    trusted_attestation_types: [:none, :basic, :self, :uncertain],
    verify_trust_root?: false,
    timeout: 60_000,
    resident_key: :required,
    sign_count_policy: :reject,
    credentials_relationship_name: :webauthn_credentials,
    registration_enabled?: true,
    sign_in_enabled?: true,
    verify_enabled?: true,
    register_action_name: nil,
    register_action_accept: [],
    sign_in_action_name: nil,
    sign_in_with_token_action_name: nil,
    verify_action_name: nil,
    __spark_metadata__: nil
  ]

  defstruct @struct_fields

  alias AshAuthentication.Strategy.{Custom, WebAuthn}

  use Custom, entity: Dsl.dsl()

  @type t :: %WebAuthn{
          name: atom,
          provider: :webauthn,
          adapter: module,
          resource: module,
          credential_resource: module,
          rp_id: String.t() | {module, atom, list} | {module, keyword},
          rp_name: String.t() | {module, atom, list} | {module, keyword},
          origin: String.t() | {module, atom, list} | {module, keyword} | nil,
          identity_field: atom,
          require_identity?: boolean,
          authenticator_attachment: nil | :platform | :cross_platform,
          user_verification: String.t(),
          attestation: String.t(),
          trusted_attestation_types: [:none | :basic | :self | :attca | :anonca | :uncertain],
          verify_trust_root?: boolean,
          timeout: pos_integer,
          resident_key: :required | :preferred | :discouraged,
          sign_count_policy: :reject | :log | :ignore,
          credentials_relationship_name: atom,
          registration_enabled?: boolean,
          sign_in_enabled?: boolean,
          verify_enabled?: boolean,
          register_action_name: atom | nil,
          register_action_accept: [atom | {atom, [secret?: boolean]}],
          sign_in_action_name: atom | nil,
          sign_in_with_token_action_name: atom | nil,
          verify_action_name: atom | nil,
          __spark_metadata__: any
        }

  alias AshAuthentication.WebAuthnCredential.Info, as: CredentialInfo

  @doc "The attribute on the credential resource which stores the WebAuthn credential ID."
  @spec credential_id_field(t()) :: atom
  def credential_id_field(strategy),
    do: credential_option!(strategy, &CredentialInfo.webauthn_credential_credential_id_field!/1)

  @doc "The attribute on the credential resource which stores the COSE public key."
  @spec public_key_field(t()) :: atom
  def public_key_field(strategy),
    do: credential_option!(strategy, &CredentialInfo.webauthn_credential_public_key_field!/1)

  @doc "The attribute on the credential resource which stores the authenticator sign count."
  @spec sign_count_field(t()) :: atom
  def sign_count_field(strategy),
    do: credential_option!(strategy, &CredentialInfo.webauthn_credential_sign_count_field!/1)

  @doc "The attribute on the credential resource which stores the WebAuthn user handle."
  @spec user_handle_field(t()) :: atom
  def user_handle_field(strategy),
    do: credential_option!(strategy, &CredentialInfo.webauthn_credential_user_handle_field!/1)

  @doc "The attribute on the credential resource which stores the client-reported transports."
  @spec transports_field(t()) :: atom
  def transports_field(strategy),
    do: credential_option!(strategy, &CredentialInfo.webauthn_credential_transports_field!/1)

  @doc "The attribute on the credential resource which stores the BE (backup eligible) flag."
  @spec backup_eligible_field(t()) :: atom
  def backup_eligible_field(strategy),
    do: credential_option!(strategy, &CredentialInfo.webauthn_credential_backup_eligible_field!/1)

  @doc "The attribute on the credential resource which stores the BS (backup state) flag."
  @spec backed_up_field(t()) :: atom
  def backed_up_field(strategy),
    do: credential_option!(strategy, &CredentialInfo.webauthn_credential_backed_up_field!/1)

  @doc "The attribute on the credential resource which stores the `credProps.rk` result."
  @spec discoverable_field(t()) :: atom
  def discoverable_field(strategy),
    do: credential_option!(strategy, &CredentialInfo.webauthn_credential_discoverable_field!/1)

  @doc "The attribute on the credential resource which stores the human-readable label."
  @spec label_field(t()) :: atom
  def label_field(strategy),
    do: credential_option!(strategy, &CredentialInfo.webauthn_credential_label_field!/1)

  @doc "The attribute on the credential resource which stores when it was last used."
  @spec last_used_at_field(t()) :: atom
  def last_used_at_field(strategy),
    do: credential_option!(strategy, &CredentialInfo.webauthn_credential_last_used_at_field!/1)

  @doc "The `belongs_to` relationship on the credential resource pointing at the user resource."
  @spec user_relationship_name(t()) :: atom
  def user_relationship_name(strategy),
    do:
      credential_option!(strategy, &CredentialInfo.webauthn_credential_user_relationship_name!/1)

  # Every option read here is declared with a default, so the getters can only
  # fail to produce a value when the section itself is absent — i.e. when the
  # credential resource doesn't use the extension. Spark would quietly hand
  # back this extension's default in that case, so check for the extension
  # first and say what's actually wrong. The compile-time verifier catches
  # this too, but only when the credential resource happens to be loaded by
  # the time the user resource is verified.
  defp credential_option!(%{credential_resource: resource}, getter) do
    unless AshAuthentication.WebAuthnCredential in Spark.extensions(resource) do
      raise ArgumentError, """
      The credential resource `#{inspect(resource)}` does not use the \
      `AshAuthentication.WebAuthnCredential` extension.

      Since 5.0 the WebAuthn strategy reads the credential's field names, \
      relationship name and action names from that extension's \
      `webauthn_credential` section, so it is required.
      """
    end

    getter.(resource)
  end

  @doc false
  defdelegate dsl(), to: Dsl
  defdelegate transform(strategy, dsl_state), to: WebAuthn.Transformer
  defdelegate verify(strategy, dsl_state), to: WebAuthn.Verifier
end
