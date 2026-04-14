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
        end
      end
    end

    relationships do
      has_many :webauthn_credentials, MyApp.Accounts.Credential
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

  You must define a separate Ash resource to store WebAuthn credentials. It needs:

  - `credential_id` (`:binary`) - the raw credential ID from the authenticator
  - `public_key` (`AshAuthentication.Strategy.WebAuthn.CoseKey`) - the COSE public key
  - `sign_count` (`:integer`) - replay attack counter
  - `label` (`:string`) - user-facing name for the credential
  - `last_used_at` (`:utc_datetime_usec`, optional) - tracks last authentication time
  - A `belongs_to` relationship to your user resource
  - A policy bypass for `AshAuthentication.Checks.AshAuthenticationInteraction`

  ### Full Example

  ```elixir
  defmodule MyApp.Accounts.Credential do
    use Ash.Resource,
      domain: MyApp.Accounts,
      data_layer: AshPostgres.DataLayer,
      authorizers: [Ash.Policy.Authorizer]

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
      attribute :credential_id, :binary, allow_nil?: false, public?: true

      attribute :public_key, AshAuthentication.Strategy.WebAuthn.CoseKey,
        allow_nil?: false, public?: true

      attribute :sign_count, :integer, default: 0, allow_nil?: false, public?: true
      attribute :label, :string, default: "Security Key", public?: true
      attribute :last_used_at, :utc_datetime_usec, public?: true
      create_timestamp :inserted_at
      update_timestamp :updated_at
    end

    relationships do
      belongs_to :user, MyApp.Accounts.User, allow_nil?: false, public?: true
    end

    identities do
      identity :unique_credential_id, [:credential_id]
    end

    actions do
      defaults [:read, :destroy]

      create :create do
        primary? true
        accept [:credential_id, :public_key, :sign_count, :label, :user_id]
      end

      update :update do
        primary? true
        accept [:sign_count, :label, :last_used_at]
      end
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
  """

  defstruct name: nil,
            resource: nil,
            credential_resource: nil,
            rp_id: nil,
            rp_name: nil,
            origin: nil,
            identity_field: :email,
            authenticator_attachment: nil,
            user_verification: "preferred",
            attestation: "none",
            timeout: 60_000,
            resident_key: :required,
            credential_id_field: :credential_id,
            public_key_field: :public_key,
            sign_count_field: :sign_count,
            label_field: :label,
            last_used_at_field: :last_used_at,
            user_relationship_name: :user,
            credentials_relationship_name: :webauthn_credentials,
            registration_enabled?: true,
            register_action_name: nil,
            sign_in_action_name: nil,
            store_credential_action_name: nil,
            update_sign_count_action_name: nil,
            list_credentials_action_name: nil,
            delete_credential_action_name: nil,
            update_credential_label_action_name: nil,
            add_credential_action_name: nil,
            __spark_metadata__: nil

  alias AshAuthentication.Strategy.{Custom, WebAuthn}

  use Custom, entity: Dsl.dsl()

  @type t :: %WebAuthn{
          name: atom,
          resource: module,
          credential_resource: module,
          rp_id: String.t() | {module, atom, list},
          rp_name: String.t() | {module, atom, list},
          origin: String.t() | {module, atom, list} | nil,
          identity_field: atom,
          authenticator_attachment: nil | :platform | :cross_platform,
          user_verification: String.t(),
          attestation: String.t(),
          timeout: pos_integer,
          resident_key: :required | :preferred | :discouraged,
          credential_id_field: atom,
          public_key_field: atom,
          sign_count_field: atom,
          label_field: atom,
          last_used_at_field: atom | nil,
          user_relationship_name: atom,
          credentials_relationship_name: atom,
          registration_enabled?: boolean,
          register_action_name: atom | nil,
          sign_in_action_name: atom | nil,
          store_credential_action_name: atom | nil,
          update_sign_count_action_name: atom | nil,
          list_credentials_action_name: atom | nil,
          delete_credential_action_name: atom | nil,
          update_credential_label_action_name: atom | nil,
          add_credential_action_name: atom | nil,
          __spark_metadata__: any
        }

  @doc false
  defdelegate dsl(), to: Dsl
  defdelegate transform(strategy, dsl_state), to: WebAuthn.Transformer
  defdelegate verify(strategy, dsl_state), to: WebAuthn.Verifier
end
