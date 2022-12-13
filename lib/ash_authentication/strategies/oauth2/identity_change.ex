defmodule AshAuthentication.Strategy.OAuth2.IdentityChange do
  @moduledoc """
  Updates the identity resource when a user is registered.
  """

  use Ash.Resource.Change
  alias AshAuthentication.{Info, UserIdentity}
  alias Ash.{Changeset, Error.Framework.AssumptionFailed, Resource.Change}
  import AshAuthentication.Utils, only: [is_falsy: 1]

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    case Info.strategy_for_action(changeset.resource, changeset.action.name) do
      {:ok, strategy} ->
        do_change(changeset, strategy)

      :error ->
        {:error,
         AssumptionFailed.exception(
           message: "Action does not correlate with an authentication strategy"
         )}
    end
  end

  defp do_change(changeset, strategy) when is_falsy(strategy.identity_resource), do: changeset

  defp do_change(changeset, strategy) do
    changeset
    |> Changeset.after_action(fn changeset, user ->
      strategy.identity_resource
      |> UserIdentity.Actions.upsert(%{
        user_info: Changeset.get_argument(changeset, :user_info),
        oauth_tokens: Changeset.get_argument(changeset, :oauth_tokens),
        strategy: strategy.name,
        user_id: user.id
      })
      |> case do
        {:ok, _identity} ->
          user
          |> changeset.api.load(strategy.identity_relationship_name)

        {:error, reason} ->
          {:error, reason}
      end
    end)
  end
end
