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
  alias AshAuthentication.{Info, Strategy, UserIdentity}
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

  # sobelow_skip ["DOS.BinToAtom"]
  defp do_change(changeset, strategy) do
    Changeset.after_action(changeset, fn changeset, user ->
      with {:ok, user_id_attribute_name} <-
             UserIdentity.Info.user_identity_user_id_attribute_name(strategy.identity_resource),
           {:ok, _identity} <-
             UserIdentity.Actions.upsert(strategy.identity_resource, %{
               user_info: Changeset.get_argument(changeset, :user_info),
               oauth_tokens: Changeset.get_argument(changeset, :oauth_tokens),
               strategy: namespaced_strategy_name(strategy),
               "#{user_id_attribute_name}": user.id
             }) do
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
          domain: Info.domain!(strategy.resource)
        )
      else
        {:error, reason} -> {:error, reason}
      end
    end)
  end

  # Namespaces the strategy name with the connection id when one is set.
  # Falls back to the bare strategy name (matching OAuth2 behaviour) when
  # called outside the dynamic_oidc plug — e.g. from a test fixture.
  defp namespaced_strategy_name(%{__connection_id__: nil} = strategy),
    do: Strategy.name(strategy) |> to_string()

  defp namespaced_strategy_name(%{__connection_id__: connection_id} = strategy),
    do: "#{Strategy.name(strategy)}/#{connection_id}"
end
