defmodule Example.Schema do
  @moduledoc false
  use Absinthe.Schema

  @apis [Example]

  use AshGraphql, apis: @apis

  def context(ctx) do
    AshGraphql.add_context(ctx, @apis)
  end

  def plugins do
    [Absinthe.Middleware.Dataloader | Absinthe.Plugin.defaults()]
  end
end
