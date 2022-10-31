defmodule Example.CurrentUserRead do
  @moduledoc """
  There's no need to actually go to the database to get the current user, when
  we know it will already be in the context.

  Here we just check that the actor is the same type of resource as is being
  asked for.
  """
  use Ash.Resource.ManualRead

  @doc false
  @impl true
  def read(%{resource: resource}, _, _, %{actor: actor}) when is_struct(actor, resource),
    do: {:ok, [actor]}

  def read(_, _, _, _), do: {:ok, []}
end
