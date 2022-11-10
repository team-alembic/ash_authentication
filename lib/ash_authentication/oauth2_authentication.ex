defmodule AshAuthentication.OAuth2Authentication do
  @dsl [
    %Spark.Dsl.Section{
      name: :oauth2_authentication,
      describe: """
      Configure generic OAuth2 authentication for this resource.
      """,
      schema: [
        provider_name: [
          type: :atom,
          doc: """
          A short name for the authentication provider.

          Used in routes, etc.
          """,
          default: :oauth2
        ],
        client_id: [
          type:
            {:spark_function_behaviour, AshAuthentication.Secret,
             {AshAuthentication.SecretFunction, 3}},
          doc: """
          The OAuth2 client ID.

          Takes either a 2..3 arity anonymous function, or a module which
          implements the `AshAuthentication.Secret` behaviour.

          See the module documentation for `AshAuthentication.Secret` for more
          information.
          """,
          required: true
        ],
        site: [
          type: :string,
          doc: "The base URL of the OAuth2 server.",
          required: true
        ],
        auth_method: [
          type:
            {:in,
             [
               nil,
               :client_secret_basic,
               :client_secret_post,
               :client_secret_jwt,
               :private_key_jwt
             ]},
          doc: """
          The authentication strategy used, optional. If not set, no
          authentication will be used during the access token request. The
          value may be one of the following:

          * `:client_secret_basic`
          * `:client_secret_post`
          * `:client_secret_jwt`
          * `:private_key_jwt`
          """,
          default: :client_secret_post
        ],
        client_secret: [
          type:
            {:spark_function_behaviour, AshAuthentication.Secret,
             {AshAuthentication.SecretFunction, 3}},
          doc: """
          The OAuth2 client secret.

          Takes either a 2..3 arity anonymous function, or a module which
          implements the `AshAuthentication.Secret` behaviour.

          See the module documentation for `AshAuthentication.Secret` for more
          information.

          Required if :auth_method is `:client_secret_basic`, `:client_secret_post` or `:client_secret_jwt`.
          """,
          required: false
        ],
        authorize_path: [
          type: :string,
          doc: "The API path to the OAuth2 authorize endpoint.",
          default: "/authorize"
        ],
        token_path: [
          type: :string,
          doc: "The API path to access the token endpoint.",
          default: "/oauth/access_token"
        ],
        user_path: [
          type: :string,
          doc: "The API path to access the user endpoint.",
          default: "/user"
        ],
        private_key: [
          type:
            {:spark_function_behaviour, AshAuthentication.Secret,
             {AshAuthentication.SecretFunction, 3}},
          doc: """
          The private key to use if `:auth_method` is `:private_key_jwt`

          Takes either a 2..3 arity anonymous function, or a module which
          implements the `AshAuthentication.Secret` behaviour.

          See the module documentation for `AshAuthentication.Secret` for more
          information.
          """,
          required: false
        ],
        redirect_uri: [
          type:
            {:spark_function_behaviour, AshAuthentication.Secret,
             {AshAuthentication.SecretFunction, 3}},
          doc: """
          The callback URI base.

          Not the whole URI back to the callback endpoint, but the URI to your
          `AuthPlug`.  We can generate the rest.

          Whilst not particularly secret, it seemed prudent to allow this to be
          configured dynamically so that you can use different URIs for
          different environments.

          Takes either a 2..3 arity anonymous function, or a module which
          implements the `AshAuthentication.Secret` behaviour.

          See the module documentation for `AshAuthentication.Secret` for more information.
          """,
          required: true
        ],
        authorization_params: [
          type: :keyword_list,
          doc: """
          Any additional parameters to encode in the request phase.

          eg: `authorization_params scope: "openid profile email"`
          """,
          default: []
        ],
        registration_enabled?: [
          type: :boolean,
          doc: """
          """,
          default: true
        ],
        sign_in_enabled?: [
          type: :boolean,
          doc: """
          """,
          default: false
        ],
        register_action_name: [
          type: :atom,
          doc: ~S"""
          The name of the action to use to register a user.

          Because we we don't know the response format of the server, you must
          implement your own registration action of the same name.  Set to
          `false` to disable registration of new users.

          See the "Registration and Sign-in" section of the module
          documentation for more information.

          The default is computed from the `provider_name` eg:
          `register_with_#{provider_name}`.
          """,
          required: false
        ],
        sign_in_action_name: [
          type: :atom,
          doc: ~S"""
          The name of the action to use to sign in an existing user.

          Because we don't know the response format of the server, you must
          implement your own sign-in action of the same name.  Set to `false`
          to disable signing in of existing users.

          See the "Registration and Sign-in" section of the module
          documentation for more information.

          The default is computed from the `provider_name`, eg:
          `sign_in_with_#{provider_name}`.
          """,
          required: false
        ],
        identity_resource: [
          type: {:or, [{:behaviour, Ash.Resource}, {:in, [false]}]},
          doc: """
          The resource used to store user identities.

          Given that a user can be signed into multiple different
          authentication providers at once we use the
          `AshAuthentication.ProviderIdentity` resource to build a mapping
          between users, providers and that provider's uid.

          See the Identities section of the module documentation for more
          information.

          Set to `false` to disable.
          """,
          default: false
        ],
        identity_relationship_name: [
          type: :atom,
          doc: "Name of the relationship to the provider identities resource",
          default: :identities
        ],
        identity_relationship_user_id_attribute: [
          type: :atom,
          doc: """
          The name of the destination (user_id) attribute on your provider identity resource.

          The only reason to change this would be if you changed the
          `user_id_attribute_name` option of the provider identity.
          """,
          default: :user_id
        ]
      ]
    }
  ]

  @moduledoc """
  Authentication using an external OAuth2 server as the source of truth.

  This extension provides support for authenticating to a generic OAuth2 server.
  Use this if a service-specific strategy is not available for your
  authentication provider.

  ## Usage

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource, extensions: [AshAuthentication, AshAuthentication.OAuth2Authentication]

    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?
    end

    oauth2_authentication do
      client_id fn _, _, _ ->
        Application.fetch_env(:my_app, :oauth2_client_id)
      end

      client_secret fn _, _, _ ->
        Application.fetch_env(:my_app, :oauth2_client_secret)
      end

      site "https://auth.example.com"

      redirect_uri fn _, _, _ ->
        "https://localhost:4000/auth"
      end
    end

    actions do
      create :oauth2_register do
        argument :user_info, :map, allow_nil?: false
        argument :oauth_tokens, :map, allow_nil?: false

        change AshAuthentication.GenerateTokenChange
        change MyApp.RegisterUser
      end
    end
  end
  ```

  ## Identities

  Given that it's possible for a user to be authenticated with more than one
  OAuth2 provider, we provide the `AshAuthentication.ProviderIdentity`
  extension.  This extension dynamically generates a resource which can be used
  to keep track of which providers a user has authenticated with, and stores any
  tokens they may have in case you wish to make requests to the service on
  behalf of the user.

  Additionally, for some providers, the provider identity resource can handle
  refreshing of access tokens before they expire.

  ## Registration and Sign-in

  You can operate your OAuth2 authentication in either registration or sign-in
  mode.  You do this by setting one of either `registration_enabled?` or
  `sign_in_enabled?` to `true`.

  ### Registration

  When registration is enabled you will need to define a create action (see the
  `register_action_name` option for details).

  This action will be called when a user successfully authenticates with the
  remote authentication provider and it will be passed two arguments:

    * `user_info` which contains the [response from the OAuth2 user info
      endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse).
    * `oauth_tokens` which the [OAuth2 token
      response](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse).

  Add a change to this action which can use this information to build a user
  record, eg:

  ```elixir
  create :register_with_oauth2 do
    argument :user_info, :map, allow_nil?: false
    argument :oauth_tokens, :map, allow_nil?: false
    upsert? true
    upsert_identity :unique_email

    change fn changeset, _ ->
      user_info = Ash.Changeset.get_argument(changeset, :user_info)

      changeset
      |> Ash.Changeset.change_attribute(:email, user_info["email"])
    end
  end
  ```

  There are likely to be additional change modules required depending on your
  configuration options.  These will be validated at compile time.

  ### Sign-in

  When registration is disabled, you will need to define a sign-in action (see
  the `sign_in_action_name` option for details).

  This action will be called with the same `user_info` and `oauth_tokens`
  arguments as the register action.  You use this action to query for an
  existing user that matches your criteria, eg:

  ```elixir
  read :sign_in_with_oauth2 do
    argument :user_info, :map, allow_nil?: false
    argument :oauth_tokens, :map, allow_nil?: false
    prepare AshAuthentication.OAuth2Authentication.SignInPreparation

    filter expr(email == get_path(^arg(:user_info), [:email]))
  end
  ```

  ## Endpoints

  This provider provides both `request` and `callback` endpoints to handle both
  phases of the request cycle.

  ## DSL Documentation

  ### Index

  #{Spark.Dsl.Extension.doc_index(@dsl)}

  ### Docs

  #{Spark.Dsl.Extension.doc(@dsl)}
  """

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [AshAuthentication.OAuth2Authentication.Transformer]

  use AshAuthentication.Provider

  alias Ash.Resource
  alias Plug.Conn

  @doc """
  The register action.

  See "Registration and Sign-in" above.
  """
  @impl true
  @spec register_action(Resource.t(), map) :: {:ok, Resource.record()} | {:error, any}
  defdelegate register_action(resource, attributes), to: __MODULE__.Actions, as: :register

  @doc """
  The sign-in action.

  See "Registration and Sign-in" above.
  """
  @impl true
  @spec sign_in_action(Resource.t(), map) :: {:ok, Resource.record()} | {:error, any}
  defdelegate sign_in_action(resource, attributes), to: __MODULE__.Actions, as: :sign_in

  @doc """
  The request plug.

  Called by the router when a request which can be handled by this provider is
  received.
  """
  @impl true
  @spec request_plug(Conn.t(), any) :: Conn.t()
  defdelegate request_plug(conn, config), to: __MODULE__.Plug, as: :request

  @doc """
  The callback plug.

  Called by the router when a user returns from the remote provider.
  """
  @impl true
  @spec callback_plug(Conn.t(), any) :: Conn.t()
  defdelegate callback_plug(conn, config), to: __MODULE__.Plug, as: :callback

  @doc false
  @impl true
  @spec has_register_step?(Resource.t()) :: boolean
  def has_register_step?(_), do: false

  @doc false
  @impl true
  def provides(resource) do
    resource
    |> __MODULE__.Info.provider_name!()
    |> to_string()
  end
end
