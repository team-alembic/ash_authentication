defmodule Example.UserWithUsername do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication, AshAuthentication.PasswordAuthentication]

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
    attribute(:hashed_password, :string, allow_nil?: false, sensitive?: true)

    create_timestamp(:created_at)
    update_timestamp(:updated_at)
  end

  actions do
    destroy :destroy do
      primary? true
    end
  end

  code_interface do
    define_for(Example)
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

  identities do
    identity(:username, [:username])
  end

  tokens do
    enabled?(true)
    revocation_resource(Example.TokenRevocation)
  end
end
