# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithFailingSender do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :email, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  postgres do
    table "user_with_failing_sender"
    repo(Example.Repo)
  end

  authentication do
    select_for_senders([:email])
    session_identifier(:jti)

    tokens do
      enabled? true
      store_all_tokens? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    add_ons do
      confirmation :confirm do
        monitor_fields [:email]
        inhibit_updates? false
        confirm_on_create? true
        confirm_on_update? true
        require_interaction? true
        sender Example.FailingSender
      end
    end

    strategies do
      password do
        identity_field :email
        hashed_password_field :hashed_password
        sign_in_tokens_enabled? true
        require_confirmed_with nil

        resettable do
          sender Example.FailingSender
        end
      end

      magic_link do
        identity_field :email
        registration_enabled? true
        require_interaction? true
        sender Example.FailingSender
      end
    end
  end

  identities do
    identity :email, [:email]
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
