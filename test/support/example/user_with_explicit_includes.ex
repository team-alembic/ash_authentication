# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithExplicitIncludes do
  @moduledoc """
  Test resource that explicitly includes specific actions for audit logging.
  Only the specified actions should be logged, not using wildcard.
  """
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
    table "users_with_explicit_includes"
    repo(Example.Repo)
  end

  authentication do
    session_identifier :jti

    tokens do
      enabled? true

      token_resource Example.Token
      signing_secret &get_config/2
    end

    add_ons do
      audit_log do
        audit_log_resource(Example.AuditLog)
        # Explicitly include only these actions - no wildcard
        include_actions([:sign_in_with_password, :register_with_password])
        # Strategies still use wildcard (default)
        include_strategies([:*])
      end
    end

    strategies do
      password do
        identity_field :email
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

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
