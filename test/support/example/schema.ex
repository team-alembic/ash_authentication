defmodule Example.Schema do
  @moduledoc false
  use Absinthe.Schema

  use AshGraphql, domains: [Example]

  query do
  end
end
