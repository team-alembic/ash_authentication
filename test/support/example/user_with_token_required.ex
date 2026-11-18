# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithTokenRequired do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  require Logger

  @type t :: %__MODULE__{
          id: Ecto.UUID.t(),
          email: String.t(),
          hashed_password: String.t(),
          created_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  attributes do
    uuid_primary_key :id, writable?: true
    attribute :email, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false
    create_timestamp :created_at
    update_timestamp :updated_at
  end

  authentication do
    tokens do
      enabled? true
      store_all_tokens? true
      require_token_presence_for_authentication? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    add_ons do
      log_out_everywhere do
        apply_on_password_change?(true)
      end

      audit_log do
        audit_log_resource(Example.AuditLog)
      end
    end

    strategies do
      password do
        identity_field :email

        resettable do
          password_reset_action_name :reset_password_with_token

          sender fn user, token, _opts ->
            Logger.debug(
              "Password reset request for user #{user.username}, token #{inspect(token)}"
            )
          end
        end
      end
    end
  end

  actions do
    defaults [:create, :read, :update, :destroy]

    update :update_email_atomic do
      require_atomic? true
      accept [:email]
    end

    update :update_email_nonatomic do
      require_atomic? false
      accept [:email]
    end

    update :change_password_atomic do
      require_atomic? true
      accept []
      argument :password, :string, allow_nil?: false, sensitive?: true
      change {AshAuthentication.Strategy.Password.HashPasswordChange, strategy_name: :password}
    end

    update :change_password_nonatomic do
      require_atomic? false
      accept []
      argument :password, :string, allow_nil?: false, sensitive?: true
      change {AshAuthentication.Strategy.Password.HashPasswordChange, strategy_name: :password}
    end

    # Written as `mix ash_authentication.add_strategy password` generates it,
    # so it is atomic, unlike the reset action the transformer would build.
    update :reset_password_with_token do
      argument :reset_token, :string do
        allow_nil? false
        sensitive? true
      end

      argument :password, :string do
        allow_nil? false
        constraints min_length: 8
        sensitive? true
      end

      argument :password_confirmation, :string do
        allow_nil? false
        sensitive? true
      end

      validate AshAuthentication.Strategy.Password.ResetTokenValidation
      validate AshAuthentication.Strategy.Password.PasswordConfirmationValidation
      change AshAuthentication.Strategy.Password.HashPasswordChange
      change AshAuthentication.GenerateTokenChange
    end
  end

  calculations do
    calculate :dummy_calc, :string, expr("dummy")
  end

  identities do
    identity :email, [:email]
  end

  postgres do
    table "user_with_token_required"
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
