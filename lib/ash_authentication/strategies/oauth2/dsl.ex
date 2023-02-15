defmodule AshAuthentication.Strategy.OAuth2.Dsl do
  @moduledoc """
  Defines the Spark DSL entity for this strategy.
  """

  alias AshAuthentication.Strategy.{Custom, OAuth2}
  alias Spark.Dsl.Entity

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    secret_type = AshAuthentication.Dsl.secret_type()
    secret_doc = AshAuthentication.Dsl.secret_doc()

    %Entity{
      name: :oauth2,
      describe: "OAuth2 authentication",
      args: [{:optional, :name, :oauth2}],
      target: OAuth2,
      modules: [
        :authorize_url,
        :client_id,
        :client_secret,
        :identity_resource,
        :private_key,
        :redirect_uri,
        :site,
        :token_url,
        :user_url
      ],
      schema: [
        name: [
          type: :atom,
          doc: """
          Uniquely identifies the strategy.
          """,
          required: true
        ],
        client_id: [
          type: secret_type,
          doc: """
          The OAuth2 client ID.

          #{secret_doc}

          Example:

          ```elixir
          client_id fn _, resource ->
            :my_app
            |> Application.get_env(resource, [])
            |> Keyword.fetch(:oauth_client_id)
          end
          ```
          """,
          required: true
        ],
        site: [
          type: secret_type,
          doc: """
          The base URL of the OAuth2 server - including the leading protocol
          (ie `https://`).

          #{secret_doc}

          Example:

          ```elixir
          site fn _, resource ->
            :my_app
            |> Application.get_env(resource, [])
            |> Keyword.fetch(:oauth_site)
          end
          ```
          """,
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
          type: secret_type,
          doc: """
          The OAuth2 client secret.

          Required if :auth_method is `:client_secret_basic`,
          `:client_secret_post` or `:client_secret_jwt`.

          #{secret_doc}

          Example:

          ```elixir
          site fn _, resource ->
            :my_app
            |> Application.get_env(resource, [])
            |> Keyword.fetch(:oauth_site)
          end
          ```
          """,
          required: false
        ],
        authorize_url: [
          type: secret_type,
          doc: """
          The API url to the OAuth2 authorize endpoint.

          Relative to the value of `site`.

          #{secret_doc}

          Example:

          ```elixir
          authorize_url fn _, _ -> {:ok, "https://exampe.com/authorize"} end
          ```
          """,
          required: true
        ],
        token_url: [
          type: secret_type,
          doc: """
          The API url to access the token endpoint.

          Relative to the value of `site`.

          #{secret_doc}

          Example:

          ```elixir
          token_url fn _, _ -> {:ok, "https://example.com/oauth_token"} end
          ```
          """,
          required: true
        ],
        user_url: [
          type: secret_type,
          doc: """
          The API url to access the user endpoint.

          Relative to the value of `site`.

          #{secret_doc}

          Example:

          ```elixir
          user_url fn _, _ -> {:ok, "https://example.com/userinfo"} end
          ```
          """,
          required: true
        ],
        private_key: [
          type: secret_type,
          doc: """
          The private key to use if `:auth_method` is `:private_key_jwt`

          #{secret_doc}
          """,
          required: false
        ],
        redirect_uri: [
          type: secret_type,
          doc: """
          The callback URI base.

          Not the whole URI back to the callback endpoint, but the URI to your
          `AuthPlug`.  We can generate the rest.

          Whilst not particularly secret, it seemed prudent to allow this to be
          configured dynamically so that you can use different URIs for
          different environments.

          #{secret_doc}
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
          Is registration enabled for this provider?

          If this option is enabled, then new users will be able to register for
          your site when authenticating and not already present.

          If not, then only existing users will be able to authenticate.
          """,
          default: true
        ],
        register_action_name: [
          type: :atom,
          doc: ~S"""
          The name of the action to use to register a user.

          Only needed if `registration_enabled?` is `true`.

          Because we we don't know the response format of the server, you must
          implement your own registration action of the same name.

          See the "Registration and Sign-in" section of the module
          documentation for more information.

          The default is computed from the strategy name eg:
          `register_with_#{name}`.
          """,
          required: false
        ],
        sign_in_action_name: [
          type: :atom,
          doc: ~S"""
          The name of the action to use to sign in an existing user.

          Only needed if `registration_enabled?` is `false`.

          Because we don't know the response format of the server, you must
          implement your own sign-in action of the same name.

          See the "Registration and Sign-in" section of the module
          documentation for more information.

          The default is computed from the strategy name, eg:
          `sign_in_with_#{name}`.
          """,
          required: false
        ],
        identity_resource: [
          type: {:or, [{:behaviour, Ash.Resource}, {:in, [false]}]},
          doc: """
          The resource used to store user identities.

          Given that a user can be signed into multiple different
          authentication providers at once we use the
          `AshAuthentication.UserIdentity` resource to build a mapping
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
          The name of the destination (user_id) attribute on your provider
          identity resource.

          The only reason to change this would be if you changed the
          `user_id_attribute_name` option of the provider identity.
          """,
          default: :user_id
        ],
        icon: [
          type: :atom,
          doc: """
          The name of an icon to use in any potential UI.

          This is a *hint* for UI generators to use, and not in any way canonical.
          """,
          required: false,
          default: :oauth2
        ]
      ],
      auto_set_fields: [assent_strategy: Assent.Strategy.OAuth2]
    }
  end
end
