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
    the *currently authenticated* user. A successful verification answers
    with a short-lived sign-in token carrying a `webauthn_verified_at` claim;
    exchanging it through `sign_in_with_token` (kept for this mode) yields a
    session token with that claim, so protected routes can require it.

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

  The **origin** is the full URL the browser signs into every WebAuthn
  ceremony (scheme + host + port). The **rp_id** is the domain name only.
  These are related but distinct:

  | Setting   | Example                    | What it is                       |
  |-----------|----------------------------|----------------------------------|
  | `rp_id`   | `"example.com"`            | Domain only (Relying Party ID)   |
  | `origin`  | `"https://example.com"`    | Full URL including scheme + port |

  Which origins a ceremony is accepted from is decided from configuration
  alone — never from the request that minted the challenge, whose scheme,
  host and port describe the proxy in front of the app as often as the
  browser's address bar. See `AshAuthentication.Strategy.WebAuthn.Origin`.

  **`origin` not set** (the default): any `https` origin whose host is the
  `rp_id` or a subdomain of it, on any port — the same set of origins a
  browser lets use that RP ID. With `rp_id "example.com"`,
  `https://example.com`, `https://app.example.com` and
  `https://app.example.com:4001` are accepted; `http://app.example.com` and
  `https://evil.com` are not. `http://localhost[:port]` is also accepted
  when the `rp_id` is `"localhost"`. The signed RP ID hash is still checked
  separately, so phishing protection does not rest on the origin alone.

  **`origin` set**: an allowlist. The browser's origin must match one of the
  configured origins exactly, port included.

  ### Narrowing to specific hosts

      origin "https://app.example.com"
      origin ["https://app.example.com", "https://admin.example.com"]

  ### Development on a non-standard port

  Nothing to configure: `https://localhost:4001` is under `rp_id "localhost"`,
  and so is `http://localhost:4000`.

  ### Multi-tenant (dynamic per tenant)

      origin {MyApp.WebAuthn, :origins_for_tenant, []}

  Behind a TLS-terminating proxy nothing needs rewriting: the connection's
  own scheme, host and port play no part.

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

  The `register` action creates a **new user** with a credential. To add a
  passkey to an already-authenticated user, use the `add_credential_challenge`
  (GET) and `add_credential` (POST) phases, or
  `AshAuthentication.Strategy.WebAuthn.Actions.add_credential/3` directly.
  Both require an authenticated actor; the challenge reuses the user handle of
  the actor's existing passkeys and lists them in `excludeCredentials`, so the
  same authenticator can't be enrolled twice.

  These phases are independent of `registration_enabled?`, `sign_in_enabled?`
  and `verify_enabled?`. They are controlled by their own options:

  - `add_credential_enabled? false` removes them.
  - `add_credential_max_authentication_age` (e.g. `{5, :minutes}`) requires the
    actor to have authenticated within that window: signed in, completed a
    second factor, or presented a bearer token issued in it. See
    `AshAuthentication.Strategy.WebAuthn.RecentAuthentication`. Unset by
    default; set it so a stolen or long-lived session can't plant a passkey.

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
    identity_field :email
    require_identity? true
  end
  ```

  Then implement the callbacks:

  ```elixir
  defmodule MyApp.WebAuthn do
    def rp_id_for_tenant(tenant), do: "\#{tenant}.example.com"
    def rp_name_for_tenant(tenant), do: "MyApp - \#{tenant}"
  end
  ```

  With no `origin` configured, each tenant's ceremonies are accepted from
  any `https` origin on that tenant's `rp_id` or a subdomain of it. To pin
  a tenant to particular origins, add a per-tenant allowlist:

  ```elixir
  origin {MyApp.WebAuthn, :origins_for_tenant, []}

  def origins_for_tenant(tenant), do: ["https://\#{tenant}.example.com"]
  ```

  The RP ID is the only per-tenant input; a request-derived `rp_id` (serving
  unrelated domains without tenancy) is not supported.

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
          require_identity? false
        end
      end
    end
  end
  ```

  No `:email` attribute, no unique identity. The browser surfaces a
  discoverable credential (passkey), and at verification time the credential
  id alone resolves the user.

  Sign-in works that way in identity mode too: the authentication challenge
  endpoint is public, so it never lists a user's credentials in
  `allowCredentials` (that would disclose them to anyone who submits the
  identity). Every sign-in therefore needs a discoverable credential, which is
  what `resident_key: :required` (the default) asks the authenticator to
  create; the strategy warns at compile time if a strategy that signs users in
  relaxes it. `require_identity?` only controls whether the user resource must
  expose an identity column.

  The companion package `ash_authentication_phoenix` needs to skip the email
  input in its sign-in components for this mode — see its documentation.

  **Gotcha:** registration creates a user with no identity, so this mode is
  unsuitable when paired with strategies that need an email on the same
  resource (e.g. password with resettable, magic link, or confirmation).

  ## Discoverable and Non-Discoverable Credentials

  A **discoverable** credential (a "resident key"; what "passkey" usually
  means) is stored on the authenticator, which keeps a record per site with
  the private key, the relying party ID and the user handle. Asked for a
  credential without being told which, the authenticator offers the ones it
  holds for the site. All synced passkeys are discoverable.

  A **non-discoverable** credential (a "server-side credential") is not
  stored. On a typical security key the credential ID *is* the private key,
  encrypted with a secret that never leaves the key. The server must send
  that ID back in `allowCredentials` before the key can use it.

  The sign-in challenge never lists credentials, so **only discoverable
  credentials can sign in**; the second-factor `verify_challenge`, whose
  caller is authenticated, lists the user's credentials and works with
  both. `resident_key` decides which kind registration asks for:

  - `:required` (default): discoverable, or registration fails.
  - `:preferred`: usually discoverable, but the authenticator may fall back
    to non-discoverable (e.g. a security key whose storage is full).
  - `:discouraged`: usually non-discoverable.

  Keep `:required` for any strategy that signs users in; the strategy warns
  at compile time otherwise. The credential's `discoverable` attribute
  records what the browser reported at registration (`true`, `false`, or
  `nil` when it didn't say). See the WebAuthn guide for more.

  ## Cross-Device (Hybrid) Passkeys

  Hybrid transport -- "use your phone or tablet", the option that shows a QR
  code -- is implemented entirely by the browser and the phone's operating
  system. The QR code, the Bluetooth proximity check and the tunnel back to the
  browser are none of this library's business: a hybrid-signed assertion is
  indistinguishable from a USB-key one and verifies through exactly the same
  path. The server's only job is to say that the option should be offered:

      webauthn do
        # ...
        hints [:hybrid, :security_key]
        timeout 300_000
      end

  That yields the two-option dialog ("use your phone or tablet" / "use your
  security key") on both sign-in and registration, so a machine with no
  authenticator of its own can enrol and then use a passkey held on a phone.
  Raise `timeout` well above the default when doing this -- a QR scan plus a
  prompt on the second device easily exceeds a minute.

  Set `allow_hint_override? true` to let a UI request one specific kind per
  ceremony (`GET .../authentication_challenge?hints=hybrid`), which is how a
  dedicated "sign in with a phone" button skips straight to the QR code.

  `hints` is a presentation preference and cannot relax verification; browsers
  which do not implement it ignore it and show their default picker.

  ## Gotchas

  - **A configured `origin` is an exact-match allowlist**, port included: with
    `origin "https://example.com"` a ceremony from `https://app.example.com` or
    `https://example.com:4001` is rejected. Leave it unset to accept every `https`
    origin on the `rp_id` or a subdomain of it, or list every origin you serve.
  - **The request's scheme, host and port are never consulted**, so a proxy needs no
    `Plug.RewriteOn` for WebAuthn's sake, and callers of the `Actions` challenge
    functions must not pass `origin:` (they raise if one does).
  - **Signing secret must return `{:ok, value}`**, not a raw string. A common mistake
    is `fn _, _ -> "my_secret" end` -- it must be `fn _, _ -> {:ok, "my_secret"} end`.
  - **Challenge data is stored in the session as plain maps**, not the adapter's own
    challenge structs, because cookie session stores cannot serialize arbitrary Elixir
    structs. The adapter serializes the challenge — origin policy included — and
    rebuilds it, re-applying the strategy's settings, before verification.
  - **Token generation happens in `Actions.sign_in`** via `Jwt.token_for_user/3`, not in
    an Ash preparation like the Password strategy. This is because the adapter verifies
    the ceremony outside the Ash action pipeline.
  - **Only the default adapter needs `wax_`.** The strategy, its plugs and the credential
    extension have no dependency on it; a custom `adapter` brings its own backend. The
    credential extension does need the `cbor` codec for the stored COSE keys, which
    `wax_` depends on — add `{:cbor, "~> 1.0"}` yourself when `wax_` isn't there.

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
    hints: [],
    allow_hint_override?: false,
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
    add_credential_enabled?: true,
    add_credential_max_authentication_age: nil,
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
          rp_id: String.t() | (any -> String.t()) | {module, atom, list} | {module, keyword},
          rp_name: String.t() | (any -> String.t()) | {module, atom, list} | {module, keyword},
          origin:
            String.t()
            | [String.t()]
            | (any -> String.t() | [String.t()])
            | {module, atom, list}
            | {module, keyword}
            | nil,
          identity_field: atom,
          require_identity?: boolean,
          authenticator_attachment: nil | :platform | :cross_platform,
          hints: [:security_key | :client_device | :hybrid],
          allow_hint_override?: boolean,
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
          add_credential_enabled?: boolean,
          add_credential_max_authentication_age:
            nil | pos_integer | {pos_integer, :days | :hours | :minutes | :seconds},
          register_action_name: atom | nil,
          register_action_accept: [atom | {atom, [secret?: boolean]}],
          sign_in_action_name: atom | nil,
          sign_in_with_token_action_name: atom | nil,
          verify_action_name: atom | nil,
          __spark_metadata__: any
        }

  alias AshAuthentication.WebAuthnCredential.Info, as: CredentialInfo

  @doc """
  Whether the strategy exchanges short-lived sign-in tokens for session tokens.

  Both `sign_in` and `verify` answer with a short-lived token (purpose
  `"sign_in"`) that is not usable as a bearer token until it is exchanged
  through the `sign_in_with_token` phase or action. That exchange therefore
  exists whenever either of them does, including a second-factor-only strategy
  (`sign_in_enabled? false`, `verify_enabled? true`).
  """
  @spec sign_in_with_token_enabled?(t()) :: boolean
  def sign_in_with_token_enabled?(strategy),
    do: strategy.sign_in_enabled? || strategy.verify_enabled?

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

  @doc """
  The attribute on the credential resource which records when it was created,
  or `nil` when it has none.

  `inserted_at` when the resource has one, else the first attribute shaped
  like a `create_timestamp` (a datetime defaulted on create, not writable and
  not touched on update). `Actions.list_credentials/3` sorts by it unless
  given a `:sort`. The extension scaffolds no such attribute, so `nil` is a
  normal answer.
  """
  @spec created_at_field(t()) :: atom | nil
  def created_at_field(%{credential_resource: resource}) do
    if Ash.Resource.Info.attribute(resource, :inserted_at) do
      :inserted_at
    else
      resource
      |> Ash.Resource.Info.attributes()
      |> Enum.find_value(&(create_timestamp?(&1) && &1.name))
    end
  end

  @datetime_types [Ash.Type.UtcDatetimeUsec, Ash.Type.UtcDatetime, Ash.Type.DateTime]

  # The shape `create_timestamp` declares: a datetime set to the current time
  # on create, never written by callers and never touched on update. (An
  # `update_timestamp` has an `update_default`.)
  defp create_timestamp?(attribute) do
    Ash.Type.get_type(attribute.type) in @datetime_types and not attribute.writable? and
      is_function(attribute.default, 0) and is_nil(attribute.update_default)
  end

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
