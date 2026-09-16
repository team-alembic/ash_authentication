# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithOAuthAuditLog do
  @moduledoc """
  Test resource which combines an OAuth2 strategy with the audit log add-on.

  The add-on persists any action field which is public and not sensitive, so
  this resource proves that the `oauth_tokens` argument stays out of the audit
  log.
  """
  use Ash.Resource,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication],
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :email, :ci_string, allow_nil?: false, public?: true

    timestamps()
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]

    create :register_with_oauth2 do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false, sensitive?: true
      upsert? true
      upsert_identity :unique_email

      change AshAuthentication.GenerateTokenChange

      change {AshAuthentication.Strategy.OAuth2.UserInfoToAttributes, fields: [email: :email]}
    end
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
      end
    end

    strategies do
      oauth2 do
        client_id &get_config/2
        redirect_uri &get_config/2
        client_secret &get_config/2
        base_url &get_config/2
        authorize_url &get_config/2
        token_url &get_config/2
        user_url &get_config/2
        warn_on_missing_identity_resource? false
        trust_email_verified? true
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
