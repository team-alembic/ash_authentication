defmodule AshAuthentication.OAuth2Authentication.IdentityChange do
  @moduledoc """
  Updates the identity resource when a user is registered.
  """

  use Ash.Resource.Change
  alias AshAuthentication.OAuth2Authentication, as: OAuth2
  alias AshAuthentication.ProviderIdentity
  alias Ash.{Changeset, Resource.Change}
  import AshAuthentication.Utils, only: [is_falsy: 1]

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    identity_resource = OAuth2.Info.identity_resource!(changeset.resource)
    maybe_change(changeset, identity_resource)
  end

  defp maybe_change(changeset, falsy) when is_falsy(falsy), do: changeset

  defp maybe_change(changeset, identity_resource) do
    identity_relationship = OAuth2.Info.identity_relationship_name!(changeset.resource)
    provider_name = OAuth2.Info.provider_name!(changeset.resource)

    changeset
    |> Changeset.after_action(fn changeset, user ->
      identity_resource
      |> ProviderIdentity.Actions.upsert(%{
        user_info: Changeset.get_argument(changeset, :user_info),
        oauth_tokens: Changeset.get_argument(changeset, :oauth_tokens),
        provider: provider_name,
        user_id: user.id
      })
      |> case do
        {:ok, _identity} ->
          user
          |> changeset.api.load(identity_relationship)

        {:error, reason} ->
          {:error, reason}
      end
    end)
  end
end
