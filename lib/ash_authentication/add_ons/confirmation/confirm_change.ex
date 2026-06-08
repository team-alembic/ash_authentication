# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.Confirmation.ConfirmChange do
  @moduledoc """
  Performs a change based on the contents of a confirmation token.
  """

  use Ash.Resource.Change
  alias AshAuthentication.{AddOn.Confirmation.Actions, Info, Jwt, UserIdentity}

  alias Ash.{
    Changeset,
    Error.Changes.InvalidArgument,
    Error.Framework.AssumptionFailed,
    Resource.Change
  }

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, context) do
    case Info.strategy_for_action(changeset.resource, changeset.action.name) do
      {:ok, strategy} ->
        do_change(changeset, strategy, context)

      :error ->
        raise AssumptionFailed,
          message: "Action does not correlate with an authentication strategy"
    end
  end

  defp do_change(changeset, strategy, context) do
    changeset
    |> Changeset.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Changeset.before_action(&apply_confirmation_token(&1, strategy, context))
  end

  defp apply_confirmation_token(changeset, strategy, context) do
    with token when is_binary(token) <-
           Changeset.get_argument(changeset, :confirm),
         {:ok, %{"act" => action, "jti" => jti}, _} <-
           Jwt.verify(token, changeset.resource, Ash.Context.to_opts(context)),
         true <-
           to_string(strategy.confirm_action_name) == action,
         {:ok, changes} <- Actions.get_changes(strategy, jti, Ash.Context.to_opts(context)) do
      allowed_changes =
        if strategy.inhibit_updates?,
          do: Map.take(changes, Enum.map(strategy.monitor_fields, &to_string/1)),
          else: %{}

      changeset
      |> Changeset.force_change_attributes(allowed_changes)
      |> Changeset.force_change_attribute(strategy.confirmed_at_field, DateTime.utc_now())
      |> maybe_link_identity(strategy, jti, context)
    else
      _ ->
        Changeset.add_error(
          changeset,
          InvalidArgument.exception(field: :confirm, message: "is not valid")
        )
    end
  end

  # `on_untrusted_email_match :confirm`: when the confirmed token carries a
  # pending provider identity link, create it once the user is confirmed. The
  # token itself is revoked by `Confirmation.Actions.confirm/3`, so the link
  # cannot be replayed.
  defp maybe_link_identity(changeset, strategy, jti, context) do
    case Actions.get_identity_link(strategy, jti, Ash.Context.to_opts(context)) do
      {:ok, payload} ->
        Changeset.after_action(changeset, fn _changeset, user ->
          link_identity(user, payload, context)
        end)

      :error ->
        changeset
    end
  end

  defp link_identity(user, payload, context) do
    with {:ok, oauth_strategy} <-
           Info.strategy(user.__struct__, String.to_existing_atom(payload["strategy"])),
         {:ok, _identity} <-
           UserIdentity.Actions.upsert(
             oauth_strategy.identity_resource,
             %{
               user_info: payload["user_info"],
               oauth_tokens: payload["oauth_tokens"],
               strategy: oauth_strategy.name,
               user_id: user.id
             },
             Ash.Context.to_opts(context)
           ) do
      {:ok, user}
    end
  end
end
