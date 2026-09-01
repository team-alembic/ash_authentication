# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithGenericPasswordReset do
  @moduledoc """
  A user whose password-reset request action is a generic action which runs
  `AshAuthentication.Strategy.Password.RequestPasswordReset`.

  This is the shape `mix ash_authentication.add_strategy` generates. The DSL
  default is a read action which uses `RequestPasswordResetPreparation`, so
  `Example.User` does not exercise this module.
  """
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
    select_for_senders [:email]

    tokens do
      enabled? true
      store_all_tokens? true
      require_token_presence_for_authentication? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    strategies do
      password do
        identity_field :email

        resettable do
          request_password_reset_action_name :request_password_reset_token

          sender fn user, token, _opts ->
            Logger.debug("Password reset request for user #{user.email}, token #{inspect(token)}")
          end
        end
      end
    end
  end

  actions do
    defaults [:create, :read, :update, :destroy]

    action :request_password_reset_token do
      description "Send password reset instructions to a user if they exist."

      argument :email, :ci_string do
        allow_nil? false
      end

      run {AshAuthentication.Strategy.Password.RequestPasswordReset, action: :get_by_email}
    end

    read :get_by_email do
      description "Looks up a user by their email"
      get_by :email
    end
  end

  identities do
    identity :email, [:email]
  end

  postgres do
    table "user_with_generic_password_reset"
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
