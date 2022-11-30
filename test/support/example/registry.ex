defmodule Example.Registry do
  @moduledoc false
  use Ash.Registry, extensions: [Ash.Registry.ResourceValidations]

  entries do
    entry Example.User
    entry Example.Token
    entry Example.UserIdentity
  end
end
