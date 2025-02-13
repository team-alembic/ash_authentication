defmodule Example.TokenWithCustomCreateTimestamp do
  @moduledoc false
  use Ash.Resource,
    extensions: [AshAuthentication.TokenResource],
    domain: Example

  attributes do
    create_timestamp :inserted_at
  end
end
