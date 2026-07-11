# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnCredential do
  @moduledoc """
  An Ash extension for WebAuthn credential resources.

  Add this extension to your credential resource to have the required
  attributes, relationship, and identity automatically scaffolded and
  validated at compile time.

  ## Usage

  ```elixir
  defmodule MyApp.Accounts.WebAuthnCredential do
    use Ash.Resource,
      domain: MyApp.Accounts,
      extensions: [AshAuthentication.WebAuthnCredential]

    webauthn_credential do
      user_resource MyApp.Accounts.User
    end
  end
  ```

  The extension automatically adds:
  - `credential_id` — binary, non-nullable, uniquely constrained
  - `public_key` — `AshAuthentication.Strategy.WebAuthn.CoseKey`, non-nullable
  - `sign_count` — integer, non-nullable, defaults to `0`
  - `user_handle` — binary, nullable; the WebAuthn user handle (`user.id`)
    baked into the passkey at registration
  - `transports` — array of strings, nullable; the transports reported by the
    client at registration (`usb`, `nfc`, `ble`, `hybrid`, `internal`, …),
    echoed back as `allowCredentials` hints
  - `backup_eligible` — boolean, nullable; the authenticator data BE flag
    (whether the credential can be synced/backed up)
  - `backed_up` — boolean, nullable; the authenticator data BS flag (whether
    the credential is currently backed up), refreshed on each assertion
  - `discoverable` — boolean, nullable; the client-reported `credProps.rk`
    value (whether the credential is a discoverable/resident key)
  - `label` — string, defaults to `"Security Key"`
  - `last_used_at` — UTC datetime, nullable
  - A `belongs_to` relationship to `user_resource` (named `:user` by default),
    with its foreign key attribute
  - A `unique_credential_id` identity on `credential_id`
  - A primary `:create` action accepting all credential fields
  - A primary `:update` action accepting `sign_count`, `label`, `last_used_at`, and `backed_up`
  - A primary `:read` action
  - A primary `:destroy` action

  Any of the above can also be declared manually instead — the extension only
  builds what's missing, and always validates the final shape (whether it
  built a field or the resource author declared it) at compile time. For
  example, to customise the relationship:

  ```elixir
    relationships do
      belongs_to :user, MyApp.Accounts.User, allow_nil?: false, public?: true
    end
  ```

  All field and relationship names are configurable via the `webauthn_credential` section.
  """

  alias AshAuthentication.Strategy.WebAuthn.CoseKey

  @dsl [
    %Spark.Dsl.Section{
      name: :webauthn_credential,
      describe: "Configuration for this WebAuthn credential resource.",
      no_depend_modules: [:user_resource],
      schema: [
        user_resource: [
          type: {:behaviour, Ash.Resource},
          doc: "The user resource to which this credential belongs.",
          required: true
        ],
        credential_id_field: [
          type: :atom,
          doc: "The name of the attribute that stores the WebAuthn credential ID.",
          default: :credential_id
        ],
        public_key_field: [
          type: :atom,
          doc: "The name of the attribute that stores the COSE public key.",
          default: :public_key
        ],
        sign_count_field: [
          type: :atom,
          doc: "The name of the attribute that stores the authenticator sign count.",
          default: :sign_count
        ],
        user_handle_field: [
          type: :atom,
          doc:
            "The name of the attribute that stores the WebAuthn user handle baked into the passkey at registration.",
          default: :user_handle
        ],
        transports_field: [
          type: :atom,
          doc:
            "The name of the attribute that stores the transports reported by the client at registration.",
          default: :transports
        ],
        backup_eligible_field: [
          type: :atom,
          doc:
            "The name of the attribute that stores the authenticator data BE (backup eligible) flag.",
          default: :backup_eligible
        ],
        backed_up_field: [
          type: :atom,
          doc:
            "The name of the attribute that stores the authenticator data BS (backup state) flag.",
          default: :backed_up
        ],
        discoverable_field: [
          type: :atom,
          doc:
            "The name of the attribute that stores the client-reported `credProps.rk` extension result (whether the credential is discoverable).",
          default: :discoverable
        ],
        label_field: [
          type: :atom,
          doc: "The name of the attribute that stores the human-readable credential label.",
          default: :label
        ],
        last_used_at_field: [
          type: :atom,
          doc:
            "The name of the optional attribute that stores when the credential was last used.",
          default: :last_used_at
        ],
        user_id_field: [
          type: :atom,
          doc:
            "The name of the foreign key attribute referencing the user (from the belongs_to).",
          default: :user_id
        ],
        user_relationship_name: [
          type: :atom,
          doc: "The name of the belongs-to relationship to the user resource.",
          default: :user
        ],
        create_action_name: [
          type: :atom,
          doc: "The name of the action used to store a new credential.",
          default: :create
        ],
        update_action_name: [
          type: :atom,
          doc: "The name of the action used to update sign count and label.",
          default: :update
        ],
        read_action_name: [
          type: :atom,
          doc: "The name of the action used to query credentials.",
          default: :read
        ],
        destroy_action_name: [
          type: :atom,
          doc: "The name of the action used to delete a credential.",
          default: :destroy
        ]
      ]
    }
  ]

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [AshAuthentication.WebAuthnCredential.Transformer]

  @doc "The `AshAuthentication.Strategy.WebAuthn.CoseKey` type used for public keys."
  def public_key_type, do: CoseKey
end
