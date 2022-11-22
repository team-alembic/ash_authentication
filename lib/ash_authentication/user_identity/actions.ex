defmodule AshAuthentication.UserIdentity.Actions do
  @moduledoc """
  Code interface for provider identity actions.

  Allows you to interact with UserIdentity resources without having to mess
  around with changesets, apis, etc.  These functions are delegated to from
  within `AshAuthentication.UserIdentity`.
  """

  alias Ash.{Changeset, Resource}
  alias AshAuthentication.UserIdentity

  @doc """
  Upsert an identity for a user.
  """
  @spec upsert(Resource.t(), map) :: {:ok, Resource.record()} | {:error, term}
  def upsert(resource, attributes) do
    with {:ok, api} <- UserIdentity.Info.user_identity_api(resource),
         {:ok, upsert_action_name} <-
           UserIdentity.Info.user_identity_upsert_action_name(resource),
         action when is_map(action) <- Resource.Info.action(resource, upsert_action_name) do
      resource
      |> Changeset.for_create(upsert_action_name, attributes,
        upsert?: true,
        upsert_identity: action.upsert_identity
      )
      |> api.create()
    end
  end
end
