defmodule AshAuthentication.Strategy.OAuth2 do
  alias __MODULE__.{Dsl, Transformer, Verifier}

  @moduledoc """
  Strategy for authenticating using an OAuth 2.0 server as the source of truth.

  This strategy wraps the excellent [`assent`](https://hex.pm/packages/assent)
  package, which provides OAuth 2.0 capabilities.

  In order to use OAuth 2.0 authentication on your resource, it needs to meet
  the following minimum criteria:

  1. Have a primary key.
  2. Provide a strategy-specific action, either register or sign-in.
  3. Provide configuration for OAuth2 destinations, secrets, etc.

  ### Example:

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
      strategies do
        oauth2 :example do
          client_id "OAuth Client ID"
          redirect_uri "https://my.app/"
          client_secret "My Super Secret Secret"
          site "https://auth.example.com/"
        end
      end
    end
  end
  ```

  ## Secrets and runtime configuration

  In order to use OAuth 2.0 you need to provide a varying number of secrets and
  other configuration which may change based on runtime environment.  The
  `AshAuthentication.Secret` behaviour is provided to accommodate this.  This
  allows you to provide configuration either directly on the resource (ie as a
  string), as an anonymous function, or as a module.

  > ### Warning {: .warning}
  >
  > We **strongly** urge you not to share actual secrets in your code or
  > repository.

  ### Examples:

  Providing configuration as an anonymous function:

  ```elixir
  oauth2 do
    client_secret fn _path, resource ->
      Application.fetch_env(:my_app, resource, :oauth2_client_secret)
    end
  end
  ```

  Providing configuration as a module:

  ```elixir
  defmodule MyApp.Secrets do
    use AshAuthentication.Secret

    def secret_for([:authentication, :strategies, :example, :client_secret], MyApp.User, _opts), do: Application.fetch_env(:my_app, :oauth2_client_secret)
  end

  # and in your strategies:

  oauth2 :example do
    client_secret MyApp.Secrets
  end
  ```

  ## User identities

  Because your users can be signed in via multiple providers at once, you can
  specify an `identity_resource` in the DSL configuration which points to a
  seperate Ash resource which has the `AshAuthentication.UserIdentity` extension
  present. This resource will be used to store details of the providers in use
  by each user and a relationship will be added to the user resource.

  Setting the `identity_resource` will cause extra validations to be applied to
  your resource so that changes are tracked correctly on sign-in or
  registration.

  ## Actions

  When using an OAuth 2.0 provider you need to declare either a "register" or
  "sign-in" action.  The reason for this is that it's not possible for us to
  know ahead of time how you want to manage the link between your user resources
  and the "user info" provided by the OAuth server.

  Both actions receive the following two arguments:

  1. `user_info` - a map with string keys containing the [OpenID Successful
     UserInfo
     response](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse).
     Usually this will be used to populate your email, nickname or other
     identifying field.
  2. `oauth_tokens` a map with string keys containing the [OpenID Successful
     Token
     response](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse)
     (or similar).

  The actions themselves can be interacted with directly via the
  `AshAuthentication.Strategy` protocol, but you are more likely to interact
  with them via the web/plugs.

  ### Sign-in

  The sign-in action is called when a successful OAuth2 callback is received.
  You should use it to constrain the query to the correct user based on the
  arguments provided.

  This action is only needed when the `registration_enabled?` DSL settings is
  set to `false`.

  ### Registration

  The register action is a little more complicated than the sign-in action,
  because we cannot tell the difference between a new user and a returning user
  (they all use the same OAuth flow).  In order to handle this your register
  action must be defined as an upsert with a configured `upsert_identity` (see
  example below).

  ### Examples:

  Providing sign-in to users who already exist in the database (and by extension
  rejecting new users):

  ```elixir
  defmodule MyApp.Accounts.User do
    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false
    end

    actions do
      read :sign_in_with_example do
        argument :user_info, :map, allow_nil?: false
        argument :oauth_tokens, :map, allow_nil?: false
        prepare AshAuthentication.Strategy.OAuth2.SignInPreparation

        filter expr(email == get_path(^arg(:user_info), [:email]))
      end
    end

    authentication do
      strategies do
        oauth2 :example do
          registration_enabled? false
        end
      end
    end
  end
  ```

  Providing registration or sign-in to all comers:

  ```elixir
  defmodule MyApp.Accounts.User do
    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false
    end

    actions do
      create :register_with_oauth2 do
        argument :user_info, :map, allow_nil?: false
        argument :oauth_tokens, :map, allow_nil?: false
        upsert? true
        upsert_identity :email

        change AshAuthentication.GenerateTokenChange
        change fn changeset, _ctx ->
          user_info = Ash.Changeset.get_argument(changeset, :user_info)

          changeset
          |> Ash.Changeset.change_attribute(:email, user_info["email"])
        end
      end
    end

    authentication do
      strategies do
        oauth2 :example do
        end
      end
    end
  end
  ```

  ## Plugs

  OAuth 2.0 is (usually) a browser-based flow. This means that you're most
  likely to interact with this strategy via it's plugs.  There are two phases to
  authentication with OAuth 2.0:

  1. The request phase, where the user's browser is redirected to the remote
     authentication provider for authentication.
  2. The callback phase, where the provider redirects the user back to your app
     to create a local database record, session, etc.
  """

  @struct_fields [
    assent_strategy: Assent.Strategy.OAuth2,
    auth_method: :client_secret_post,
    authorization_params: [],
    authorize_url: nil,
    base_url: nil,
    client_authentication_method: nil,
    client_id: nil,
    client_secret: nil,
    icon: nil,
    id_token_signed_response_alg: nil,
    id_token_ttl_seconds: nil,
    identity_relationship_name: :identities,
    identity_relationship_user_id_attribute: :user_id,
    identity_resource: false,
    name: nil,
    nonce: false,
    openid_configuration_uri: nil,
    openid_configuration: nil,
    private_key: nil,
    provider: :oauth2,
    redirect_uri: nil,
    register_action_name: nil,
    registration_enabled?: true,
    resource: nil,
    sign_in_action_name: nil,
    site: nil,
    strategy_module: __MODULE__,
    token_url: nil,
    trusted_audiences: nil,
    user_url: nil
  ]

  defstruct @struct_fields

  alias AshAuthentication.Strategy.{Custom, OAuth2}

  use Custom, entity: Dsl.dsl()

  @type secret :: nil | String.t() | {module, keyword}

  @type t :: %OAuth2{
          assent_strategy: module,
          auth_method:
            nil
            | :client_secret_basic
            | :client_secret_post
            | :client_secret_jwt
            | :private_key_jwt,
          authorization_params: keyword,
          authorize_url: secret,
          base_url: secret,
          client_authentication_method: nil | atom,
          client_id: secret,
          client_secret: secret,
          icon: nil | atom,
          id_token_signed_response_alg: nil | binary,
          id_token_ttl_seconds: nil | pos_integer(),
          identity_relationship_name: atom,
          identity_relationship_user_id_attribute: atom,
          identity_resource: module | false,
          name: atom,
          nonce: boolean | secret,
          openid_configuration_uri: nil | binary,
          openid_configuration: nil | map,
          private_key: secret,
          provider: atom,
          redirect_uri: secret,
          register_action_name: atom,
          registration_enabled?: boolean,
          resource: module,
          sign_in_action_name: atom,
          site: secret,
          strategy_module: module,
          token_url: secret,
          trusted_audiences: nil | [binary],
          user_url: secret
        }

  @doc false
  defdelegate dsl, to: Dsl
  defdelegate transform(strategy, dsl_state), to: Transformer
  defdelegate verify(strategy, dsl_state), to: Verifier
end
