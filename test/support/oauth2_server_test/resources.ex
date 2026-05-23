# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# Test fixtures for the OAuth2Server core. Lives in a self-contained ETS
# domain so it doesn't interact with the Postgres-backed Example resources.

defmodule Oauth2ServerTest.Hammer do
  @moduledoc false
  use Hammer, backend: :ets
end

defmodule Oauth2ServerTest.User do
  @moduledoc false
  use Ash.Resource,
    domain: Oauth2ServerTest.Domain,
    data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :email, :ci_string, public?: true, allow_nil?: false
  end

  actions do
    defaults [:read, :destroy]
    create :create, accept: [:email]
  end
end

defmodule Oauth2ServerTest.OAuthClient do
  @moduledoc false
  use Ash.Resource,
    domain: Oauth2ServerTest.Domain,
    data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :client_name, :string, public?: true, allow_nil?: false
    attribute :redirect_uris, {:array, :string}, public?: true, allow_nil?: false, default: []
    attribute :grant_types, {:array, :string}, public?: true, default: ["authorization_code"]
    attribute :response_types, {:array, :string}, public?: true, default: ["code"]
    attribute :token_endpoint_auth_method, :string, public?: true, default: "none"
    attribute :scope, :string, public?: true, default: "mcp"
    attribute :last_used_at, :utc_datetime_usec, public?: true
    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  actions do
    defaults [:read, :destroy]

    create :register do
      accept [
        :client_name,
        :redirect_uris,
        :grant_types,
        :response_types,
        :token_endpoint_auth_method,
        :scope
      ]
    end

    update :touch do
      accept []
      require_atomic? false
      change set_attribute(:last_used_at, &DateTime.utc_now/0)
    end
  end
end

defmodule Oauth2ServerTest.OAuthAuthorizationCode do
  @moduledoc false
  use Ash.Resource,
    domain: Oauth2ServerTest.Domain,
    data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :redirect_uri, :string, allow_nil?: false, public?: true
    attribute :code_challenge, :string, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true
    attribute :resource_uri, :string, allow_nil?: false, public?: true
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false, public?: true
    attribute :consumed_at, :utc_datetime_usec, public?: true
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      accept [
        :client_id,
        :user_id,
        :redirect_uri,
        :code_challenge,
        :scope,
        :resource_uri,
        :expires_at
      ]
    end

    update :consume do
      accept []
      require_atomic? false

      change fn changeset, _ ->
        if Ash.Changeset.get_data(changeset, :consumed_at) do
          Ash.Changeset.add_error(changeset,
            field: :consumed_at,
            message: "code already used"
          )
        else
          Ash.Changeset.change_attribute(changeset, :consumed_at, DateTime.utc_now())
        end
      end
    end
  end
end

defmodule Oauth2ServerTest.OAuthRefreshToken do
  @moduledoc false
  use Ash.Resource,
    domain: Oauth2ServerTest.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication.Oauth2Server.RefreshTokenResource]

  attributes do
    # Writable so the Token core can rotate-with-pre-allocated-id atomically.
    uuid_v7_primary_key :id, writable?: true
    attribute :token_hash, :string, allow_nil?: false, public?: true
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true
    attribute :resource_uri, :string, allow_nil?: false, public?: true
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false, public?: true
    attribute :rotated_to_id, :uuid_v7, public?: true
    attribute :revoked_at, :utc_datetime_usec, public?: true
  end

  actions do
    defaults [:read, :destroy]

    create :issue do
      accept [:id, :token_hash, :client_id, :user_id, :scope, :resource_uri, :expires_at]
    end

    update :rotate do
      argument :rotated_to_id, :uuid_v7, allow_nil?: false
      accept []
      require_atomic? false

      # The change attaches the atomic filter + sets the attribute. The
      # `RefreshTokenResource` verifier checks for its presence so the
      # contract can't silently be broken by editing the action.
      change AshAuthentication.Oauth2Server.Changes.RotateRefreshToken
    end

    update :revoke do
      accept []
      require_atomic? false
      change set_attribute(:revoked_at, &DateTime.utc_now/0)
    end
  end

  identities do
    identity :by_token_hash, [:token_hash], pre_check_with: Oauth2ServerTest.Domain
  end
end

defmodule Oauth2ServerTest.OAuthConsent do
  @moduledoc false
  use Ash.Resource,
    domain: Oauth2ServerTest.Domain,
    data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true

    attribute :granted_at, :utc_datetime_usec,
      allow_nil?: false,
      public?: true,
      default: &DateTime.utc_now/0
  end

  actions do
    defaults [:read, :destroy]

    create :grant do
      upsert? true
      upsert_identity :by_user_client
      accept [:user_id, :client_id, :scope]
    end
  end

  identities do
    identity :by_user_client, [:user_id, :client_id], pre_check_with: Oauth2ServerTest.Domain
  end
end

defmodule Oauth2ServerTest.Domain do
  @moduledoc false
  use Ash.Domain

  resources do
    resource Oauth2ServerTest.User
    resource Oauth2ServerTest.OAuthClient
    resource Oauth2ServerTest.RateLimitedOAuthClient
    resource Oauth2ServerTest.OAuthAuthorizationCode
    resource Oauth2ServerTest.OAuthRefreshToken
    resource Oauth2ServerTest.OAuthConsent
  end
end

defmodule Oauth2ServerTest.Secrets do
  @moduledoc false
  use AshAuthentication.Secret

  @impl AshAuthentication.Secret
  def secret_for([:issuer_url], _, _, _), do: {:ok, "https://app.example.com"}
  def secret_for([:resource_url], _, _, _), do: {:ok, "https://app.example.com/mcp"}

  def secret_for([:signing_secret], _, _, _),
    do: {:ok, "test-signing-secret-test-signing-secret"}

  def secret_for([:initial_access_token], _, _, _),
    do: {:ok, "test-initial-access-token-shhh"}

  def secret_for(_, _, _, _), do: :error
end

defmodule Oauth2ServerTest.Server do
  @moduledoc false
  use AshAuthentication.Oauth2Server,
    otp_app: :ash_authentication,
    user_resource: Oauth2ServerTest.User,
    issuer_url: {Oauth2ServerTest.Secrets, []},
    resource_url: {Oauth2ServerTest.Secrets, []},
    signing_secret: {Oauth2ServerTest.Secrets, []},
    client_resource: Oauth2ServerTest.OAuthClient,
    authorization_code_resource: Oauth2ServerTest.OAuthAuthorizationCode,
    refresh_token_resource: Oauth2ServerTest.OAuthRefreshToken,
    consent_resource: Oauth2ServerTest.OAuthConsent,
    scopes: ["mcp"],
    dcr_enabled?: true
end

defmodule Oauth2ServerTest.GatedServer do
  @moduledoc """
  Identical to `Oauth2ServerTest.Server` but with `:initial_access_token`
  configured, so DCR requires the request to present the matching bearer.
  """

  use AshAuthentication.Oauth2Server,
    otp_app: :ash_authentication,
    user_resource: Oauth2ServerTest.User,
    issuer_url: {Oauth2ServerTest.Secrets, []},
    resource_url: {Oauth2ServerTest.Secrets, []},
    signing_secret: {Oauth2ServerTest.Secrets, []},
    client_resource: Oauth2ServerTest.OAuthClient,
    authorization_code_resource: Oauth2ServerTest.OAuthAuthorizationCode,
    refresh_token_resource: Oauth2ServerTest.OAuthRefreshToken,
    consent_resource: Oauth2ServerTest.OAuthConsent,
    initial_access_token: {Oauth2ServerTest.Secrets, []},
    scopes: ["mcp"],
    dcr_enabled?: true
end

defmodule Oauth2ServerTest.DcrDisabledServer do
  @moduledoc """
  Default configuration — `dcr_enabled?` defaults to false. Used to test
  that `POST /oauth/register` is gated off and that the metadata document
  omits `registration_endpoint`.
  """

  use AshAuthentication.Oauth2Server,
    otp_app: :ash_authentication,
    user_resource: Oauth2ServerTest.User,
    issuer_url: {Oauth2ServerTest.Secrets, []},
    resource_url: {Oauth2ServerTest.Secrets, []},
    signing_secret: {Oauth2ServerTest.Secrets, []},
    client_resource: Oauth2ServerTest.OAuthClient,
    authorization_code_resource: Oauth2ServerTest.OAuthAuthorizationCode,
    refresh_token_resource: Oauth2ServerTest.OAuthRefreshToken,
    consent_resource: Oauth2ServerTest.OAuthConsent,
    scopes: ["mcp"]
end

defmodule Oauth2ServerTest.UnenforcedScopesServer do
  @moduledoc """
  Identical to `Oauth2ServerTest.Server` but with `enforce_scopes?: false`,
  so any requested scope is accepted at `/authorize`.
  """

  use AshAuthentication.Oauth2Server,
    otp_app: :ash_authentication,
    user_resource: Oauth2ServerTest.User,
    issuer_url: {Oauth2ServerTest.Secrets, []},
    resource_url: {Oauth2ServerTest.Secrets, []},
    signing_secret: {Oauth2ServerTest.Secrets, []},
    client_resource: Oauth2ServerTest.OAuthClient,
    authorization_code_resource: Oauth2ServerTest.OAuthAuthorizationCode,
    refresh_token_resource: Oauth2ServerTest.OAuthRefreshToken,
    consent_resource: Oauth2ServerTest.OAuthConsent,
    scopes: ["mcp"],
    enforce_scopes?: false,
    dcr_enabled?: true
end

defmodule Oauth2ServerTest.ScopeProvider do
  @moduledoc """
  Test stub used by `Oauth2ServerTest.DynamicScopesServer` to exercise
  the `{Module, function, args}` form of the `:scopes` option.
  """

  @doc "Returns the dynamically-computed scope catalogue."
  @spec list_scopes() :: [String.t()]
  def list_scopes, do: ["mcp", "dynamic.scope"]
end

defmodule Oauth2ServerTest.DynamicScopesServer do
  @moduledoc """
  Uses an MFA tuple for `:scopes`, so the catalogue is computed by
  calling `Oauth2ServerTest.ScopeProvider.list_scopes/0`.
  """

  use AshAuthentication.Oauth2Server,
    otp_app: :ash_authentication,
    user_resource: Oauth2ServerTest.User,
    issuer_url: {Oauth2ServerTest.Secrets, []},
    resource_url: {Oauth2ServerTest.Secrets, []},
    signing_secret: {Oauth2ServerTest.Secrets, []},
    client_resource: Oauth2ServerTest.OAuthClient,
    authorization_code_resource: Oauth2ServerTest.OAuthAuthorizationCode,
    refresh_token_resource: Oauth2ServerTest.OAuthRefreshToken,
    consent_resource: Oauth2ServerTest.OAuthConsent,
    scopes: {Oauth2ServerTest.ScopeProvider, :list_scopes, []},
    dcr_enabled?: true
end

defmodule Oauth2ServerTest.RateLimitedOAuthClient do
  @moduledoc """
  Mirrors `Oauth2ServerTest.OAuthClient` but adds an `AshRateLimiter`
  block with a very low `:register` ceiling so the rate-limit path can
  be exercised in a test.
  """

  use Ash.Resource,
    domain: Oauth2ServerTest.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshRateLimiter]

  rate_limit do
    backend Oauth2ServerTest.Hammer

    action :register,
      limit: 2,
      per: :timer.minutes(1),
      key: &AshAuthentication.Oauth2Server.RateLimit.key_by_ip/2
  end

  attributes do
    uuid_v7_primary_key :id
    attribute :client_name, :string, public?: true, allow_nil?: false
    attribute :redirect_uris, {:array, :string}, public?: true, allow_nil?: false, default: []
    attribute :grant_types, {:array, :string}, public?: true, default: ["authorization_code"]
    attribute :response_types, {:array, :string}, public?: true, default: ["code"]
    attribute :token_endpoint_auth_method, :string, public?: true, default: "none"
    attribute :scope, :string, public?: true, default: "mcp"
    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  actions do
    defaults [:read, :destroy]

    create :register do
      accept [
        :client_name,
        :redirect_uris,
        :grant_types,
        :response_types,
        :token_endpoint_auth_method,
        :scope
      ]
    end
  end
end

defmodule Oauth2ServerTest.RateLimitedServer do
  @moduledoc """
  Server using `RateLimitedOAuthClient` so tests can drive the
  `:rate_limited` return path of `Register.register/3`.
  """

  use AshAuthentication.Oauth2Server,
    otp_app: :ash_authentication,
    user_resource: Oauth2ServerTest.User,
    issuer_url: {Oauth2ServerTest.Secrets, []},
    resource_url: {Oauth2ServerTest.Secrets, []},
    signing_secret: {Oauth2ServerTest.Secrets, []},
    client_resource: Oauth2ServerTest.RateLimitedOAuthClient,
    authorization_code_resource: Oauth2ServerTest.OAuthAuthorizationCode,
    refresh_token_resource: Oauth2ServerTest.OAuthRefreshToken,
    consent_resource: Oauth2ServerTest.OAuthConsent,
    scopes: ["mcp"],
    dcr_enabled?: true
end
