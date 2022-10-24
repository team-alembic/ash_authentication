defmodule Example.TokenRevocation do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.TokenRevocation]

  @type t :: %__MODULE__{
          jti: String.t(),
          expires_at: DateTime.t()
        }

  actions do
    destroy :expire
  end

  postgres do
    table("token_revocations")
    repo(Example.Repo)
  end

  revocation do
    api Example
  end
end
