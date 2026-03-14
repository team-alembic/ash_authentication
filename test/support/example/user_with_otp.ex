# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithOtp do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  require Logger

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :email, :ci_string, allow_nil?: false, public?: true

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  postgres do
    table "user_with_otp"
    repo(Example.Repo)
  end

  actions do
    defaults [:read]

    create :create do
      primary? true
      accept [:email]
    end
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

    strategies do
      otp do
        identity_field :email
        otp_lifetime {10, :minutes}
        otp_length 6
        otp_characters :uppercase_letters

        sender fn user, otp_code, _opts ->
          Logger.info("OTP request for #{user.email}, code #{inspect(otp_code)}")
        end
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
