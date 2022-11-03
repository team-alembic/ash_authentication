defmodule Example.Registry do
  @moduledoc false
  use Ash.Registry, extensions: [Ash.Registry.ResourceValidations]

  entries do
    entry Example.UserWithUsername
    entry Example.TokenRevocation
    entry Example.UserIdentity
  end
end
