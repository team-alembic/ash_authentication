# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.OidcConnection do
  @dsl [
    %Spark.Dsl.Section{
      name: :oidc_connection,
      describe: "Configure storage of dynamic OIDC connection rows.",
      no_depend_modules: [:domain],
      schema: [
        domain: [
          type: {:behaviour, Ash.Domain},
          doc: "The Ash domain used to access this resource.",
          required: false
        ],
        id_attribute_name: [
          type: :atom,
          doc: "The name of the primary-key attribute.",
          default: :id
        ],
        base_url_field: [
          type: :atom,
          doc: """
          The name of an attribute or calculation that returns the OIDC issuer
          base URL for the connection (e.g. `https://acme.okta.com/oauth2/default`).
          """,
          default: :base_url
        ],
        client_id_field: [
          type: :atom,
          doc: "The name of an attribute or calculation that returns the OAuth2 client_id.",
          default: :client_id
        ],
        client_secret_field: [
          type: :atom,
          doc: """
          The name of an attribute or calculation that returns the OAuth2
          client_secret. If you encrypt secrets at rest (recommended — see
          `ash_cloak`/`cloak_ecto`), expose a calculation that decrypts on
          load and point this option at it.
          """,
          default: :client_secret
        ],
        display_name_field: [
          type: {:or, [:atom, nil]},
          doc:
            "Optional attribute/calculation returning a human-readable name for the connection (used by UI). Set to `nil` to disable.",
          default: :display_name
        ],
        icon_url_field: [
          type: {:or, [:atom, nil]},
          doc:
            "Optional attribute/calculation returning an icon URL for the connection (used by UI). Set to `nil` to disable.",
          default: :icon_url
        ],
        read_action_name: [
          type: :atom,
          doc: "The name of the action used to read connections.",
          default: :read
        ]
      ]
    }
  ]

  @moduledoc """
  An Ash extension for resources that store dynamic OIDC connection
  configuration — used by `AshAuthentication.Strategy.DynamicOidc` to look up
  the OIDC client config at request time instead of pinning it at compile time.

  This is the resource layer for the data-driven SSO pattern: each row is one
  customer's OIDC client configuration (base_url, client_id, client_secret,
  plus optional display name/icon for UI). At sign-in time the strategy
  queries the resource — typically scoped by the current Ash tenant — and
  builds an ephemeral OAuth2 strategy from the matched row.

  ## Usage

  ```elixir
  defmodule MyApp.Accounts.OidcConnection do
    use Ash.Resource,
      data_layer: AshPostgres.DataLayer,
      extensions: [AshAuthentication.OidcConnection],
      domain: MyApp.Accounts

    oidc_connection do
      # All defaults shown — override only what you need.
      base_url_field :base_url
      client_id_field :client_id
      client_secret_field :client_secret
      display_name_field :display_name
      icon_url_field :icon_url
    end

    postgres do
      table "oidc_connections"
      repo MyApp.Repo
    end
  end
  ```

  The extension generates default attributes (string columns for
  `base_url`, `client_id`, `client_secret`, `display_name`, `icon_url`) and a
  default `:read` action. You're free to:

    - Replace any field with an Ash calculation (e.g. one that decrypts the
      client_secret on load) and point the field config at it.
    - Add multitenancy, custom attributes, additional actions, and
      authorization policies as you see fit.

  ## Authorization

  If you enable `Ash.Policy.Authorizer` on this resource, you must allow the
  framework to read connections during the OIDC flow. The simplest way is a
  bypass:

      policies do
        bypass AshAuthentication.Checks.AshAuthenticationInteraction do
          authorize_if always()
        end

        # ... your own policies for admin UI write operations
      end

  ## Secret storage

  Storing client_secret as a plaintext string is convenient but dangerous if
  the database is compromised. Encrypt it at rest with `ash_cloak` (or
  `cloak_ecto`), and point `client_secret_field` at a calculation that
  decrypts on load.

  ## Multitenancy

  This extension does not require multitenancy. If your resource is
  multitenant, the strategy will scope connection lookups by the current Ash
  tenant automatically. If it isn't, the strategy will look up connections
  globally — useful for single-tenant deployments with multiple IdPs.
  """

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [
      AshAuthentication.OidcConnection.Transformer
    ]
end
