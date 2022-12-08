defmodule Example.User do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [
      AshAuthentication,
      AshGraphql.Resource,
      AshJsonApi.Resource
    ]

  require Logger

  @type t :: %__MODULE__{
          id: Ecto.UUID.t(),
          username: String.t(),
          hashed_password: String.t(),
          created_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  attributes do
    uuid_primary_key(:id, writable?: true)

    attribute(:username, :ci_string, allow_nil?: false)
    attribute(:hashed_password, :string, allow_nil?: true, sensitive?: true, private?: true)

    create_timestamp(:created_at)
    update_timestamp(:updated_at)
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
      primary? true
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

    read :sign_in_with_oauth2 do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      prepare AshAuthentication.Strategy.OAuth2.SignInPreparation

      filter expr(username == get_path(^arg(:user_info), [:nickname]))
    end
  end

  graphql do
    type :user

    queries do
      get(:get_user, :read)
      list(:list_users, :read)
      read_one(:current_user, :current_user)
    end

    mutations do
      create :register, :register_with_password
    end
  end

  json_api do
    type "user"

    routes do
      base("/users")
      get(:read)
      get(:current_user, route: "/me")
      index(:read)
      post(:register_with_password)
    end
  end

  postgres do
    table("user")
    repo(Example.Repo)
  end

  authentication do
    api(Example)

    tokens do
      enabled?(true)
      token_resource(Example.Token)
      signing_secret(&get_config/2)
    end

    add_ons do
      confirmation :confirm do
        monitor_fields([:username])
        inhibit_updates?(true)

        sender(fn user, token ->
          Logger.debug("Confirmation request for user #{user.username}, token #{inspect(token)}")
        end)
      end
    end

    strategies do
      password :password do
        resettable do
          sender(fn user, token ->
            Logger.debug(
              "Password reset request for user #{user.username}, token #{inspect(token)}"
            )
          end)
        end
      end

      oauth2 :oauth2 do
        client_id(&get_config/2)
        redirect_uri(&get_config/2)
        client_secret(&get_config/2)
        site(&get_config/2)
        authorize_path(&get_config/2)
        token_path(&get_config/2)
        user_path(&get_config/2)
        authorization_params(scope: "openid profile email")
        auth_method(:client_secret_post)
        identity_resource(Example.UserIdentity)
      end
    end
  end

  identities do
    identity(:username, [:username], eager_check_with: Example)
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
