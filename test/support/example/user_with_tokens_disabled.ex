# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithTokensDisabled do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :email, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false

    timestamps()
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]
  end

  postgres do
    table "users_with_tokens_disabled"
    repo(Example.Repo)
  end

  authentication do
    strategies do
      password do
        identity_field :email
        sign_in_tokens_enabled? false
      end
    end
  end

  identities do
    identity :unique_email, [:email]
  end

  code_interface do
    define :sign_in_with_password
    define :register_with_password
  end
end
