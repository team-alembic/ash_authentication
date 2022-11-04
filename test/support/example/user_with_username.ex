defmodule Example.UserWithUsername do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [
      AshAuthentication,
      AshAuthentication.Confirmation,
      AshAuthentication.PasswordAuthentication,
      AshAuthentication.PasswordReset,
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
    uuid_primary_key(:id)

    attribute(:username, :ci_string, allow_nil?: false)
    attribute(:hashed_password, :string, allow_nil?: false, sensitive?: true, private?: true)

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
  end

  code_interface do
    define_for(Example)
  end

  confirmation do
    monitor_fields([:username])
    inhibit_updates?(true)

    sender(fn user, token ->
      Logger.debug("Confirmation request for user #{user.username}, token #{inspect(token)}")
    end)
  end

  graphql do
    type :user

    queries do
      get(:get_user, :read)
      list(:list_users, :read)
      read_one(:current_user, :current_user)
    end

    mutations do
      create :register, :register
    end
  end

  json_api do
    type "user"

    routes do
      base("/users")
      get(:read)
      get(:current_user, route: "/me")
      index(:read)
      post(:register)
    end
  end

  postgres do
    table("user_with_username")
    repo(Example.Repo)
  end

  authentication do
    api(Example)
  end

  password_authentication do
    identity_field(:username)
    hashed_password_field(:hashed_password)
  end

  password_reset do
    sender(fn user, token ->
      Logger.debug("Password reset request for user #{user.username}, token #{inspect(token)}")
    end)
  end

  identities do
    identity(:username, [:username], eager_check_with: Example)
  end

  tokens do
    enabled?(true)
    revocation_resource(Example.TokenRevocation)
  end
end
