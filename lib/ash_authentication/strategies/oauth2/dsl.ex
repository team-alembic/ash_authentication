# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

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
    secret_list_type = AshAuthentication.Dsl.secret_list_type()
    secret_keyword_type = AshAuthentication.Dsl.secret_keyword_type()
    secret_doc = AshAuthentication.Dsl.secret_doc()

    %Entity{
      name: :oauth2,
      describe: "OAuth2 authentication",
      args: [{:optional, :name, :oauth2}],
      target: OAuth2,
      no_depend_modules: [
        :authorize_url,
        :base_url,
        :client_id,
        :client_secret,
        :identity_resource,
        :private_key,
        :private_key_id,
        :private_key_path,
        :redirect_uri,
        :site,
        :token_url,
        :user_url,
        :code_verifier
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
          doc: "The OAuth2 client ID.  #{secret_doc}",
          required: true
        ],
        base_url: [
          type: secret_type,
          doc:
            "The base URL of the OAuth2 server - including the leading protocol (ie `https://`).  #{secret_doc}",
          required: false
        ],
        site: [
          type: secret_type,
          doc: "Deprecated: Use `base_url` instead.",
          required: false
        ],
        prevent_hijacking?: [
          type: :boolean,
          default: true,
          doc:
            "Requires a confirmation add_on to be present if the password strategy is used with the same identity_field."
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
          doc:
            "The authentication strategy used, optional. If not set, no authentication will be used during the access token request.",
          default: :client_secret_post
        ],
        client_secret: [
          type: secret_type,
          doc:
            "The OAuth2 client secret. Required if :auth_method is `:client_secret_basic`, `:client_secret_post` or `:client_secret_jwt`. #{secret_doc}",
          required: false
        ],
        authorize_url: [
          type: secret_type,
          doc:
            "The API url to the OAuth2 authorize endpoint, relative to `site`, e.g `authorize_url fn _, _ -> {:ok, \"https://exampe.com/authorize\"} end`. #{secret_doc}",
          required: true
        ],
        token_url: [
          type: secret_type,
          doc:
            "The API url to access the token endpoint, relative to `site`, e.g `token_url fn _, _ -> {:ok, \"https://example.com/oauth_token\"} end`. #{secret_doc}",
          required: true
        ],
        trusted_audiences: [
          type: secret_list_type,
          doc: """
          A list of audiences which are trusted. #{secret_doc}
          """,
          required: false,
          default: nil
        ],
        user_url: [
          type: secret_type,
          doc:
            "The API url to access the user endpoint, relative to `site`, e.g `user_url fn _, _ -> {:ok, \"https://example.com/userinfo\"} end`. #{secret_doc}",
          required: true
        ],
        private_key: [
          type: secret_type,
          doc: "The private key to use if `:auth_method` is `:private_key_jwt`. #{secret_doc}",
          required: false
        ],
        private_key_id: [
          type: secret_type,
          doc:
            "The identifier of the private key (sent as `kid` in the JWT header) if `:auth_method` is `:private_key_jwt`. #{secret_doc}",
          required: false
        ],
        private_key_path: [
          type: secret_type,
          doc:
            "Path to the private key PEM file (alternative to `:private_key`) if `:auth_method` is `:private_key_jwt`. #{secret_doc}",
          required: false
        ],
        redirect_uri: [
          type: secret_type,
          doc:
            "The callback URI *base*. Not the whole URI back to the callback endpoint, but the URI to your `AuthPlug`. #{secret_doc}",
          required: true
        ],
        code_verifier: [
          type: :boolean,
          doc:
            "Boolean to generate and use a random 128 byte long url safe code verifier for PKCE flow, optional, defaults to false. When set to true the session params will contain :code_verifier, :code_challenge, and :code_challenge_method params",
          default: false
        ],
        authorization_params: [
          type: secret_keyword_type,
          doc:
            "Any additional parameters to encode in the request phase. eg: `authorization_params scope: \"openid profile email\"`",
          default: []
        ],
        registration_enabled?: [
          type: :boolean,
          doc:
            "If enabled, new users will be able to register for your site when authenticating and not already present. If not, only existing users will be able to authenticate.",
          default: true
        ],
        register_action_name: [
          type: :atom,
          doc:
            "The name of the action to use to register a user, if `registration_enabled?` is `true`. Defaults to `register_with_<name>` See the \"Registration and Sign-in\" section of the strategy docs for more.",
          required: false
        ],
        sign_in_action_name: [
          type: :atom,
          doc:
            "The name of the action to use to sign in an existing user, if `sign_in_enabled?` is `true`. Defaults to `sign_in_with_<strategy>`, which is generated for you by default. See the \"Registration and Sign-in\" section of the strategy docs for more information.",
          required: false
        ],
        identity_resource: [
          type: {:or, [{:behaviour, Ash.Resource}, {:in, [false]}]},
          doc:
            "The resource used to store user identities. Required: matching users by email or other provider claims is unsafe, so the provider's `iss`/`sub` claims must be persisted. See the User Identities section of the strategy docs for more.",
          default: false
        ],
        warn_on_missing_identity_resource?: [
          type: :boolean,
          doc:
            "Whether to emit a compile-time warning when no `identity_resource` is configured. Set to `false` only when you have deliberately chosen not to use an identity resource and accept that users are matched by provider claims such as email, which is unsafe and will become unsupported in a future release.",
          default: true
        ],
        trust_email_verified?: [
          type: :boolean,
          doc:
            "Whether the provider's `email_verified` claim can be trusted to attach an OAuth2 sign-in to a pre-existing local account with the same email. Only enable this for providers that reliably assert email ownership. When `false`, a sign-in whose `iss`/`sub` is not yet known will never be matched to an existing account by email.",
          default: false
        ],
        on_untrusted_email_match: [
          type: {:one_of, [:reject, :confirm]},
          doc:
            "What to do when a new `iss`/`sub` presents an email matching an existing account but the email can't be trusted (see `trust_email_verified?`). `:reject` (the default) refuses the sign-in. `:confirm` issues a confirmation to the existing account's email and links the provider only once the recipient proves ownership; requires a `confirmation` add-on. Note: confirming binds whatever provider identity initiated the flow, so the confirmation email must make clear which provider is being linked - otherwise a user can be tricked into linking an attacker's provider account.",
          default: :reject
        ],
        identity_relationship_name: [
          type: :atom,
          doc: "Name of the relationship to the provider identities resource",
          default: :identities
        ],
        identity_relationship_user_id_attribute: [
          type: :atom,
          doc:
            "The name of the destination (user_id) attribute on your provider identity resource. Only necessary if you've changed the `user_id_attribute_name` option of the provider identity.",
          default: :user_id
        ],
        icon: [
          type: :atom,
          doc:
            " The name of an icon to use in any potential UI. This is a *hint* for UI generators to use, and not in any way canonical.",
          required: false,
          default: :oauth2
        ]
      ],
      deprecations: [site: "As of assent v0.2.8 please use `base_url` instead."],
      auto_set_fields: [assent_strategy: Assent.Strategy.OAuth2],
      transform: {__MODULE__, :transform, []}
    }
  end

  @doc false
  @spec transform(Custom.entity()) :: {:ok, Custom.entity()} | {:error, any}
  def transform(entity) do
    handle_site_deprecation(entity)
  end

  defp handle_site_deprecation(entity) when is_nil(entity.base_url) and not is_nil(entity.site),
    do: {:ok, %{entity | base_url: entity.site, site: nil}}

  defp handle_site_deprecation(entity), do: {:ok, entity}
end
