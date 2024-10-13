defmodule Example.User do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [
      AshAuthentication,
      AshGraphql.Resource,
      AshJsonApi.Resource,
      Example.OnlyMartiesAtTheParty
    ],
    domain: Example

  require Logger

  @type t :: %__MODULE__{
          id: Ecto.UUID.t(),
          username: String.t(),
          hashed_password: String.t(),
          created_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :username, :ci_string, allow_nil?: false, public?: true
    attribute :extra_stuff, :string, public?: true
    attribute :not_accepted_extra_stuff, :string
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  actions do
    read :read do
      primary? true
    end

    destroy :destroy do
      primary? true
    end

    read :current_user do
      get? true
      manual Example.CurrentUserRead
    end

    update :update do
      argument :password, :string, allow_nil?: true, sensitive?: true
      argument :password_confirmation, :string, allow_nil?: true, sensitive?: true
      accept [:username]
      primary? true
      require_atomic? false
    end

    create :register_with_auth0 do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :username

      change AshAuthentication.GenerateTokenChange
      change Example.GenericOAuth2Change
      change AshAuthentication.Strategy.OAuth2.IdentityChange
    end

    create :register_with_oauth2 do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :username

      change AshAuthentication.GenerateTokenChange
      change Example.GenericOAuth2Change
      change AshAuthentication.Strategy.OAuth2.IdentityChange
    end

    create :register_with_oidc do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :username

      change AshAuthentication.GenerateTokenChange
      change Example.GenericOAuth2Change
      change AshAuthentication.Strategy.OAuth2.IdentityChange
    end

    read :sign_in_with_oauth2 do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      prepare AshAuthentication.Strategy.OAuth2.SignInPreparation

      filter expr(username == get_path(^arg(:user_info), [:nickname]))
    end

    read :sign_in_with_oauth2_without_identity do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      prepare AshAuthentication.Strategy.OAuth2.SignInPreparation

      filter expr(username == get_path(^arg(:user_info), [:nickname]))
    end

    create :register_with_github do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :username

      change AshAuthentication.GenerateTokenChange
      change Example.GenericOAuth2Change
      change AshAuthentication.Strategy.OAuth2.IdentityChange
    end
  end

  code_interface do
    define :update_user, action: :update
  end

  graphql do
    type :user

    queries do
      get :get_user, :read
      list :list_users, :read
      read_one :current_user, :current_user
    end

    mutations do
      create :register, :register_with_password
    end
  end

  json_api do
    type "user"

    routes do
      base "/users"
      get :read
      get :current_user, route: "/me"
      index :read
      post :register_with_password
    end
  end

  postgres do
    table "user"
    repo(Example.Repo)
  end

  authentication do
    select_for_senders([:username])

    tokens do
      enabled? true
      store_all_tokens? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    add_ons do
      confirmation :confirm do
        monitor_fields [:username]
        inhibit_updates? true

        sender fn _user, token, opts ->
          username =
            opts
            |> Keyword.fetch!(:changeset)
            |> Ash.Changeset.get_attribute(:username)

          Logger.debug("Confirmation request for user #{username}, token #{inspect(token)}")
        end
      end
    end

    strategies do
      password do
        register_action_accept [:extra_stuff]
        sign_in_tokens_enabled? true

        resettable do
          sender fn user, token, _opts ->
            Logger.debug(
              "Password reset request for user #{user.username}, token #{inspect(token)}"
            )
          end
        end
      end

      oauth2 do
        client_id &get_config/2
        redirect_uri &get_config/2
        client_secret &get_config/2
        base_url &get_config/2
        authorize_url &get_config/2
        token_url &get_config/2
        trusted_audiences &get_config/2
        user_url &get_config/2
        authorization_params scope: "openid profile email"
        auth_method :client_secret_post
        identity_resource Example.UserIdentity
      end

      oauth2 :oauth2_without_identity do
        client_id &get_config/2
        redirect_uri &get_config/2
        client_secret &get_config/2
        base_url &get_config/2
        authorize_url &get_config/2
        token_url &get_config/2
        user_url &get_config/2
        authorization_params scope: "openid profile email"
        auth_method :client_secret_post
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
      end

      github do
        client_id &get_config/2
        redirect_uri &get_config/2
        client_secret &get_config/2
        authorization_params scope: "openid profile email"
      end

      only_marty do
        case_sensitive?(false)
        name_field(:username)
      end

      magic_link do
        sender fn user, token, _opts ->
          Logger.debug("Magic link request for #{user.username}, token #{inspect(token)}")
        end
      end

      oidc do
        authorization_params scope: "openid profile email phone address"
        client_id &get_config/2
        client_secret &get_config/2
        redirect_uri &get_config/2
        base_url &get_config/2
        trusted_audiences &get_config/2
      end
    end
  end

  identities do
    identity :username, [:username]
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
