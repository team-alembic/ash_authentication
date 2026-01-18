# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule ExampleMultiTenant.GlobalUser do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: ExampleMultiTenant

  attributes do
    uuid_primary_key(:id, writable?: true)

    attribute(:username, :ci_string, allow_nil?: false, public?: true)
    attribute(:hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false)

    create_timestamp(:created_at)
    update_timestamp(:updated_at)
  end

  actions do
    defaults [:read, :destroy]

    read :sign_in_with_api_key_global do
      argument :api_key, :string, allow_nil?: false
      prepare AshAuthentication.Strategy.ApiKey.SignInPreparation
    end
  end

  postgres do
    table("global_user")
    repo(Example.Repo)
  end

  authentication do
    select_for_senders([:username])
    subject_name :global_user
    session_identifier(:jti)

    tokens do
      enabled? true
      token_resource ExampleMultiTenant.Token
      signing_secret &get_config/2
    end

    strategies do
      password do
        sign_in_tokens_enabled? true
        require_confirmed_with nil
      end

      api_key :api_key_global do
        api_key_relationship :valid_api_keys
        api_key_hash_attribute :api_key_hash
      end
    end
  end

  identities do
    identity(:username, [:username])
  end

  relationships do
    has_many :valid_api_keys, ExampleMultiTenant.ApiKey do
      filter expr(valid)
    end
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
