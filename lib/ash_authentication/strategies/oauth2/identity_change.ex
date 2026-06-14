# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.IdentityChange do
  @moduledoc """
  Resolves and updates the user's identity when registering via OAuth2/OIDC.

  Runs in two phases:

    * `before_action` - resolves *which* local user this sign-in belongs to,
      using the provider's `iss`/`sub` (never the email). See
      `AshAuthentication.Strategy.OAuth2.UserResolver` for the matching rules.
    * `after_action` - upserts the identity row for the resolved user so that
      future sign-ins with the same `iss`/`sub` resolve to them.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Error.Framework.AssumptionFailed, Resource.Change}
  alias AshAuthentication.{Info, Strategy, Strategy.OAuth2, UserIdentity}
  import AshAuthentication.Utils, only: [is_falsy: 1]
  require Ash.Query

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
         {:ok, _identity} <-
           UserIdentity.Actions.upsert(
             strategy.identity_resource,
             %{
               user_id_attribute_name => user.id,
               user_info: Changeset.get_argument(changeset, :user_info),
               oauth_tokens: Changeset.get_argument(changeset, :oauth_tokens),
               strategy: Strategy.name(strategy)
             },
             opts
           ) do
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
