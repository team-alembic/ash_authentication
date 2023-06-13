defmodule Example.Schema do
  @moduledoc false
  use Absinthe.Schema

  @apis [Example]

  use AshGraphql, apis: @apis

  query do
  end
end
