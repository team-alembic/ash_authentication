defmodule AshAuthentication.UserIdentity do
  @dsl [
    %Spark.Dsl.Section{
      name: :user_identity,
      describe: "Configure identity options for this resource",
      no_depend_modules: [:domain, :user_resource],
      schema: [
        domain: [
          type: {:behaviour, Ash.Domain},
          doc: "The Ash domain to use to access this resource.",
          required: false
        ],
        user_resource: [
          type: {:behaviour, Ash.Resource},
          doc: "The user resource to which these identities belong.",
          required: true
        ],
        uid_attribute_name: [
          type: :atom,
          doc: "The name of the `uid` attribute on this resource.",
          default: :uid
        ],
        strategy_attribute_name: [
          type: :atom,
          doc: "The name of the `strategy` attribute on this resource.",
          default: :strategy
        ],
        user_id_attribute_name: [
          type: :atom,
          doc: "The name of the `user_id` attribute on this resource.",
          default: :user_id
        ],
        access_token_attribute_name: [
          type: :atom,
          doc: "The name of the `access_token` attribute on this resource.",
          default: :access_token
        ],
        access_token_expires_at_attribute_name: [
          type: :atom,
          doc: "The name of the `access_token_expires_at` attribute on this resource.",
          default: :access_token_expires_at
        ],
        refresh_token_attribute_name: [
          type: :atom,
          doc: "The name of the `refresh_token` attribute on this resource.",
          default: :refresh_token
        ],
        upsert_action_name: [
          type: :atom,
          doc: "The name of the action used to create and update records.",
          default: :upsert
        ],
        destroy_action_name: [
          type: :atom,
          doc: "The name of the action used to destroy records.",
          default: :destroy
        ],
        read_action_name: [
          type: :atom,
          doc: "The name of the action used to query identities.",
          default: :read
        ],
        user_relationship_name: [
          type: :atom,
          doc: "The name of the belongs-to relationship between identities and users.",
          default: :user
        ]
      ]
    }
  ]

  @moduledoc """
  An Ash extension which generates the default user identities resource.

  If you plan to support multiple different strategies at once (eg giving your
  users the choice of more than one authentication provider, or signing them into
  multiple services simultaneously) then you will want to create a resource with
  this extension enabled. It is used to keep track of the links between your
  local user records and their many remote identities.

  The user identities resource is used to store information returned by remote
  authentication strategies (such as those provided by OAuth2) and maps them to
  your user resource(s).  This provides the following benefits:

    1. A user can be signed in to multiple authentication strategies at once.
    2. For those providers that support it, AshAuthentication can handle
       automatic refreshing of tokens.

  ## Storage

  User identities are expected to be relatively long-lived (although they're
  deleted on log out), so should probably be stored using a permanent data layer
  sush as `ash_postgres`.

  ## Usage

  There is no need to define any attributes, etc.  The extension will generate
  them all for you.  As there is no other use-case for this resource it's
  unlikely that you will need to customise it.

  ```elixir
  defmodule MyApp.Accounts.UserIdentity do
    use Ash.Resource,
      data_layer: AshPostgres.DataLayer,
      extensions: [AshAuthentication.UserIdentity],
      domain: MyApp.Accounts

    user_identity do
      user_resource MyApp.Accounts.User
    end

    postgres do
      table "user_identities"
      repo MyApp.Repo
    end
  end
  ```

  If you intend to operate with multiple user resources, you will need to define
  multiple user identity resources.
  """

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [
      AshAuthentication.UserIdentity.Transformer,
      AshAuthentication.UserIdentity.Verifier
    ]
end
