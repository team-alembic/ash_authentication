defmodule Example.RecoveryCode do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :code, :string, sensitive?: true, allow_nil?: false, public?: false

    timestamps()
  end

  relationships do
    belongs_to :user, Example.UserWithRecoveryCodes, allow_nil?: false
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:code]
    end
  end

  postgres do
    table "recovery_codes"
    repo(Example.Repo)

    references do
      reference(:user, on_delete: :delete)
    end
  end
end
