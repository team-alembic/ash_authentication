# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithRenamedAuditLog do
  @moduledoc """
  Test resource whose audit log add-on does not use the default name.

  The transformer marks actions which belong to no strategy with the name
  `:audit_log`, which is also the default name of the add-on. This resource
  proves that the marker stays valid when no add-on carries that name.
  """
  use Ash.Resource,
    data_layer: Ash.DataLayer.Ets,
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

  authentication do
    session_identifier :jti

    tokens do
      enabled? true

      token_resource Example.Token
      signing_secret &get_config/2
    end

    add_ons do
      audit_log :security_log do
        audit_log_resource(Example.AuditLog)
      end
    end

    strategies do
      password do
        identity_field :email
      end
    end
  end

  identities do
    identity :unique_email, [:email], pre_check_with: Example
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
