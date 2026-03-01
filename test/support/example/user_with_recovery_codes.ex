defmodule Example.UserWithRecoveryCodes do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :email, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false

    timestamps()
  end

  relationships do
    has_many :recovery_codes, Example.RecoveryCode do
      destination_attribute :user_id
    end
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]
  end

  postgres do
    table "recovery_code_users"
    repo(Example.Repo)
  end

  authentication do
    session_identifier :jti

    tokens do
      enabled? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    strategies do
      password do
        identity_field :email
      end

      recovery_code do
        recovery_code_resource Example.RecoveryCode
        hash_provider AshAuthentication.BcryptProvider
        brute_force_strategy {:preparation, Example.TotpNoopPreparation}
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
