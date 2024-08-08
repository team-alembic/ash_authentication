defmodule AshAuthentication.TokenResource do
  @default_expunge_interval_hrs 12

  @dsl [
    %Spark.Dsl.Section{
      name: :token,
      describe: "Configuration options for this token resource",
      no_depend_modules: [:domain],
      schema: [
        domain: [
          type: {:behaviour, Ash.Domain},
          required: false,
          doc: """
          The Ash domain to use to access this resource.
          """
        ],
        expunge_expired_action_name: [
          type: :atom,
          doc: """
          The name of the action used to remove expired tokens.
          """,
          default: :expunge_expired
        ],
        read_expired_action_name: [
          type: :atom,
          doc: "The name of the action use to find all expired tokens.",
          default: :read_expired
        ],
        expunge_interval: [
          type: :pos_integer,
          doc:
            "How often to scan this resource for records which have expired, and thus can be removed.",
          default: @default_expunge_interval_hrs
        ],
        store_token_action_name: [
          type: :atom,
          doc:
            "The name of the action to use to store a token, if `require_tokens_for_authentication?` is enabled in your authentication resource.",
          default: :store_token
        ],
        get_token_action_name: [
          type: :atom,
          doc:
            "The name of the action used to retrieve tokens from the store, if `require_tokens_for_authentication?` is enabled in your authentication resource.",
          default: :get_token
        ]
      ],
      sections: [
        %Spark.Dsl.Section{
          name: :revocation,
          describe: "Configuration options for token revocation",
          schema: [
            revoke_token_action_name: [
              type: :atom,
              doc: """
              The name of the action used to revoke tokens.
              """,
              default: :revoke_token
            ],
            is_revoked_action_name: [
              type: :atom,
              doc: """
              The name of the action used to check if a token is revoked.
              """,
              default: :revoked?
            ]
          ]
        },
        %Spark.Dsl.Section{
          name: :confirmation,
          describe: "Configuration options for confirmation tokens",
          schema: [
            store_changes_action_name: [
              type: :atom,
              doc: """
              The name of the action used to store confirmation changes.
              """,
              default: :store_confirmation_changes
            ],
            get_changes_action_name: [
              type: :atom,
              doc: """
              The name of the action used to get confirmation changes.
              """,
              default: :get_confirmation_changes
            ]
          ]
        }
      ]
    }
  ]

  @moduledoc """
  This is an Ash resource extension which generates the default token resource.

  The token resource is used to store information about tokens that should not
  be shared with the end user.  It does not actually contain any tokens.

  For example:

    * When an authentication token has been revoked
    * When a confirmation token has changes to apply

  ## Storage

  The information stored in this resource is essentially ephemeral - all tokens
  have an expiry date, so it doesn't make sense to keep them after that time has
  passed.  However, if you have any tokens with very long expiry times then we
  suggest you store this resource in a resilient data-layer such as Postgres.

  ## Usage

  There is no need to define any attributes or actions (although you can if you
  want).  The extension will wire up everything that's needed for the token
  system to function.

  ```
  defmodule MyApp.Accounts.Token do
    use Ash.Resource,
      data_layer: AshPostgres.DataLayer,
      extensions: [AshAuthentication.TokenResource],
      domain: MyApp.Accounts

    postgres do
      table "tokens"
      repo MyApp.Repo
    end
  end
  ```

  Whilst it is possible to have multiple token resources, there is no need to do
  so.

  ## Removing expired records

  Once a token has expired there's no point in keeping the information it refers
  to, so expired tokens can be automatically removed by adding the
  `AshAuthentication.Supervisor` to your application supervision tree.  This
  will start the `AshAuthentication.TokenResource.Expunger` `GenServer` which
  periodically scans and removes any expired records.
  """

  alias Ash.Resource
  alias AshAuthentication.TokenResource

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [TokenResource.Transformer, TokenResource.Verifier]

  @doc """
  Has the token been revoked?

  Similar to `jti_revoked?/2..3` except that it extracts the JTI from the token,
  rather than relying on it to be passed in.
  """
  @spec token_revoked?(Resource.t(), String.t(), keyword) :: boolean
  defdelegate token_revoked?(resource, token, opts \\ []), to: TokenResource.Actions

  @doc """
  Has the token been revoked?

  Similar to `token-revoked?/2..3` except that rather than extracting the JTI
  from the token, assumes that it's being passed in directly.
  """
  @spec jti_revoked?(Resource.t(), String.t(), keyword) :: boolean
  defdelegate jti_revoked?(resource, jti, opts \\ []), to: TokenResource.Actions

  @doc """
  Revoke a token.

  Extracts the JTI from the provided token and uses it to generate a revocation
  record.
  """
  @spec revoke(Resource.t(), String.t(), keyword) :: :ok | {:error, any}
  defdelegate revoke(resource, token, opts \\ []), to: TokenResource.Actions

  @doc """
  Remove all expired records.
  """
  @spec expunge_expired(Resource.t(), keyword) :: :ok | {:error, any}
  defdelegate expunge_expired(resource, opts \\ []), to: TokenResource.Actions
end
