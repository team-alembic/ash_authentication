# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithRegisterOtp do
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
    table "user_with_register_otp"
    repo(Example.Repo)
  end

  actions do
    defaults [:read]
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
        registration_enabled? true
        otp_lifetime {10, :minutes}
        otp_length 6
        otp_characters :unambiguous_uppercase

        sender fn user_or_email, otp_code, _opts ->
          email =
            if is_binary(user_or_email) do
              user_or_email
            else
              user_or_email.email
            end

          Logger.info("OTP request for #{email}, code #{inspect(otp_code)}")
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
