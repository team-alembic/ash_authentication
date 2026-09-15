# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithOauth2Email do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :email, :ci_string, allow_nil?: true, public?: true
    attribute :username, :ci_string, allow_nil?: true, public?: true

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  postgres do
    table "user_with_oauth2_email"
    repo(Example.Repo)
  end

  actions do
    defaults [:read]

    create :register_with_github do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false, sensitive?: true
      upsert? true
      upsert_identity :unique_email

      change AshAuthentication.GenerateTokenChange
      change {AshAuthentication.Strategy.OAuth2.UserInfoToAttributes, fields: [:email]}
      change AshAuthentication.Strategy.OAuth2.IdentityChange
    end

    create :register_with_google do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false, sensitive?: true
      upsert? true
      upsert_identity :unique_username

      change AshAuthentication.GenerateTokenChange
      change Example.GenericOAuth2Change
      change {AshAuthentication.Strategy.OAuth2.UserInfoToAttributes, fields: [:email]}
      change AshAuthentication.Strategy.OAuth2.IdentityChange
    end

    # Filtered on the username while trusting the provider's `email_verified`
    # claim - the sign-in shape where the claim attests nothing about the
    # account the filter matched.
    read :sign_in_with_slack do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false, sensitive?: true
      prepare AshAuthentication.Strategy.OAuth2.SignInPreparation

      filter expr(username == get_path(^arg(:user_info), [:nickname]))
    end

    # Filtered on the email, which the verified claim does attest.
    read :sign_in_with_auth0 do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false, sensitive?: true
      prepare AshAuthentication.Strategy.OAuth2.SignInPreparation

      filter expr(email == get_path(^arg(:user_info), [:email]))
    end
  end

  authentication do
    session_identifier(:jti)

    tokens do
      enabled? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    strategies do
      # Keyed on the email, which is the only shape that can auto-attach a
      # sign-in to an existing account.
      github do
        client_id &get_config/2
        redirect_uri &get_config/2
        client_secret &get_config/2
        identity_resource Example.UserWithOauth2EmailIdentity
      end

      # Keyed on the username while trusting the provider's `email_verified`
      # claim - the shape where the claim attests nothing about the account.
      google do
        client_id &get_config/2
        redirect_uri &get_config/2
        client_secret &get_config/2
        identity_resource Example.UserWithOauth2EmailIdentity
      end

      # The same two shapes on the sign-in path, where the action's filter
      # stands in for the upsert identity. Both leave
      # `trust_email_verified?` at the provider default of `true`.
      slack do
        client_id &get_config/2
        redirect_uri &get_config/2
        client_secret &get_config/2
        identity_resource Example.UserWithOauth2EmailIdentity
        registration_enabled? false
      end

      auth0 do
        client_id &get_config/2
        redirect_uri &get_config/2
        client_secret &get_config/2
        base_url &get_config/2
        authorize_url &get_config/2
        token_url &get_config/2
        user_url &get_config/2
        identity_resource Example.UserWithOauth2EmailIdentity
        registration_enabled? false
      end
    end
  end

  identities do
    identity :unique_email, [:email]
    identity :unique_username, [:username]
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
