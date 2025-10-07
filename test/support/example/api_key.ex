# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.ApiKey do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    domain: Example

  attributes do
    uuid_primary_key :id

    attribute :api_key_hash, :binary, allow_nil?: false, public?: true

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :user, Example.User do
      public? true
      attribute_writable? true
      primary_key? true
      allow_nil? false
    end
  end

  postgres do
    table "api_keys"
    repo(Example.Repo)
  end

  policies do
    bypass always() do
      authorize_if AshAuthentication.Checks.AshAuthenticationInteraction
    end
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:user_id]

      change {AshAuthentication.Strategy.ApiKey.GenerateApiKey, prefix: :aap, hash: :api_key_hash}
    end
  end
end
