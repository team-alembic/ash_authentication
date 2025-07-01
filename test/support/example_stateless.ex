defmodule ExampleStateless do
  @moduledoc false
  use Ash.Domain, extensions: [AshAuthentication.Domain]

  resources do
    resource ExampleStateless.User
    resource ExampleStateless.Token
  end
end
