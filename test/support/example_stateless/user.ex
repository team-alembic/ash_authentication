defmodule ExampleStateless.User do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: ExampleStateless

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
    subject_name(:stateless_user)
    session_identifier(:jti)

    tokens do
      enabled? true
      # store_all_tokens? defaults to false - this is what we want to test
      token_resource ExampleStateless.Token
      signing_secret &get_config/2
    end

    strategies do
      password do
        identity_field :email
      end
    end
  end

  actions do
    defaults [:create, :read, :update, :destroy]
  end

  calculations do
    calculate :dummy_calc, :string, expr("dummy")
  end

  identities do
    identity :email, [:email]
  end

  postgres do
    table "stateless_user"
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
