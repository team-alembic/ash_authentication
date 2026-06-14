# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.DynamicOidc.IdentityChange do
  @moduledoc """
  Updates the identity resource when a user is registered through a
  `dynamic_oidc` strategy, namespacing the `strategy` field with the
  matched connection id so the `{user_id, uid, strategy}` unique
  constraint disambiguates between IdPs that may issue colliding
  `sub` claims.

  Drop this change into your `register_with_*` action **instead of**
  `AshAuthentication.Strategy.OAuth2.IdentityChange`:

      change AshAuthentication.Strategy.DynamicOidc.IdentityChange
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Error.Framework.AssumptionFailed, Resource.Change}
  alias AshAuthentication.{Info, Strategy.OAuth2, UserIdentity}
  import AshAuthentication.Utils, only: [is_falsy: 1]

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, context) do
    case Info.strategy_for_action(changeset.resource, changeset.action.name) do
      {:ok, strategy} ->
        do_change(changeset, strategy, context)

      :error ->
        {:error,
         AssumptionFailed.exception(
           message: "Action does not correlate with an authentication strategy"
         )}
    end
  end

  defp do_change(changeset, strategy, _context) when is_falsy(strategy.identity_resource),
    do: changeset

  defp do_change(changeset, strategy, context) do
    opts = [tenant: context.tenant, actor: context.actor]

    changeset
    |> Changeset.before_action(&OAuth2.UserResolver.resolve(&1, strategy, opts))
    |> Changeset.after_action(&upsert_identity(&1, &2, strategy, opts))
  end

  defp upsert_identity(changeset, user, strategy, opts) do
    with {:ok, user_id_attribute_name} <-
           UserIdentity.Info.user_identity_user_id_attribute_name(strategy.identity_resource),
         attrs <-
           %{
             user_info: Changeset.get_argument(changeset, :user_info),
             oauth_tokens: Changeset.get_argument(changeset, :oauth_tokens),
             strategy: OAuth2.identity_strategy_name(strategy)
           }
           |> Map.put(user_id_attribute_name, user.id),
         {:ok, _identity} <-
           UserIdentity.Actions.upsert(strategy.identity_resource, attrs, opts) do
      user
      |> Ash.load(
        [
          {strategy.identity_relationship_name,
           Ash.Query.new(strategy.identity_resource)
           |> Ash.Query.set_context(%{
             private: %{
               ash_authentication?: true
             }
           })}
        ],
        Keyword.put(opts, :domain, Info.domain!(strategy.resource))
      )
    else
      {:error, reason} -> {:error, reason}
    end
  end
end
