# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithAuditLog do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :email, :ci_string, allow_nil?: false, public?: true, sensitive?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false

    attribute :totp_secret, :binary, allow_nil?: true, sensitive?: true, public?: false

    attribute :last_totp_at, :datetime, allow_nil?: true, sensitive?: true, public?: false

    timestamps()
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]
  end

  postgres do
    table "audit_logged_users"
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
        include_fields([:email])
      end
    end

    strategies do
      password do
        identity_field :email

        resettable do
          sender fn _user, _token, _opts -> :ok end
        end
      end

      magic_link do
        identity_field :email
        sender fn _user, _token, _opts -> :ok end
      end

      remember_me :remember_me do
        sign_in_action_name :sign_in_with_remember_me
        cookie_name :remember_me_audit_log
        token_lifetime {30, :days}
      end

      totp do
        identity_field :email
        sign_in_enabled? true
        brute_force_strategy({:audit_log, :audit_log})
      end
    end
  end

  identities do
    identity :unique_email, [:email]
  end

  code_interface do
    define :sign_in_with_password
  end

  # calculations do
  #   calculate :totp_url_for_totp,
  #             :string,
  #             {AshAuthentication.Strategy.Totp.TotpUrlCalculation, strategy_name: :totp},
  #             load: [:email, :totp_secret]
  # end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
