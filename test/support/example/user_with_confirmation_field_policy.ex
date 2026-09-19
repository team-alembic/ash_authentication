# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithConfirmationFieldPolicy do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshAuthentication],
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true
    attribute :email, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false
    attribute :confirmed_at, :utc_datetime_usec, allow_nil?: true, public?: true
  end

  authentication do
    session_identifier :jti

    tokens do
      enabled? true
      store_all_tokens? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    strategies do
      password do
        identity_field :email
        register_action_accept [:confirmed_at]
        sign_in_tokens_enabled? true
        require_confirmed_with :confirmed_at
      end
    end
  end

  actions do
    defaults [:read, :destroy]
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    policy always() do
      authorize_if always()
    end
  end

  field_policies do
    field_policy :confirmed_at do
      authorize_if actor_present()
    end

    field_policy :* do
      authorize_if always()
    end
  end

  identities do
    identity :email, [:email]
  end

  postgres do
    table "user_with_confirmation_field_policy"
    repo(Example.Repo)
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
