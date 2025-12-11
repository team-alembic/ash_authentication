# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithTotpConfirmSetup do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :email, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false
    attribute :totp_secret, :binary, allow_nil?: true, sensitive?: true, public?: false
    attribute :last_totp_at, :datetime, allow_nil?: true, sensitive?: true, public?: false

    timestamps()
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]
  end

  postgres do
    table "totp_confirm_setup_users"
    repo(Example.Repo)
  end

  authentication do
    session_identifier :jti

    tokens do
      enabled? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    strategies do
      password do
        identity_field :email
      end

      totp do
        identity_field :email
        sign_in_enabled? true
        confirm_setup_enabled?(true)
        brute_force_strategy({:preparation, Example.TotpNoopPreparation})
      end
    end
  end

  identities do
    identity :unique_email, [:email]
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
