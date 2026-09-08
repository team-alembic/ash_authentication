# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.Confirmation.ConfirmChange do
  @moduledoc """
  Performs a change based on the contents of a confirmation token.
  """

  use Ash.Resource.Change

  alias AshAuthentication.{
    AddOn.Confirmation.Actions,
    Errors.InvalidToken,
    Info,
    Jwt,
    TokenResource,
    UserIdentity
  }

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
    opts = Ash.Context.to_opts(context)

    with token when is_binary(token) <-
           Changeset.get_argument(changeset, :confirm),
         {:ok, %{"act" => action, "jti" => jti, "sub" => subject}, _} <-
           Jwt.verify(token, changeset.resource, opts),
         true <-
           to_string(strategy.confirm_action_name) == action,
         true <-
           subject_matches_record?(changeset, subject),
         {:ok, token_resource} <-
           Info.authentication_tokens_token_resource(changeset.resource),
         {:ok, changes} <- Actions.get_changes(strategy, jti, opts) do
      allowed_changes =
        if strategy.inhibit_updates?,
          do: Map.take(changes, Enum.map(strategy.monitor_fields, &to_string/1)),
          else: %{}

      changeset
      |> Changeset.force_change_attributes(allowed_changes)
      |> Changeset.force_change_attribute(strategy.confirmed_at_field, DateTime.utc_now())
      |> maybe_link_identity(strategy, jti, context)
      |> revoke_token(token_resource, token, opts)
    else
      _ ->
        Changeset.add_error(
          changeset,
          InvalidArgument.exception(field: :confirm, message: "is not valid")
        )
    end
  end

  # The token names the record it was issued for in its `sub` claim. Without
  # this comparison the stored changes for one user are applied to whichever
  # record the caller points the action at.
  #
  # The primary key is compared against `changeset.data` rather than resolved
  # with `AshAuthentication.subject_to_user/3`: the record is already loaded,
  # so a second read only adds a query which a customised `get_by_subject`
  # action could answer with a different record.
  defp subject_matches_record?(changeset, subject) do
    subject_name =
      changeset.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    with %URI{path: ^subject_name, query: query} when is_binary(query) <- URI.parse(subject),
         [_ | _] = primary_key <- Ash.Resource.Info.primary_key(changeset.resource) do
      token_primary_key = URI.decode_query(query)

      Enum.all?(primary_key, fn field ->
        Map.get(token_primary_key, to_string(field)) ==
          to_string(Map.get(changeset.data, field))
      end)
    else
      _ -> false
    end
  end

  # Confirmation tokens are single use. `Confirmation.Actions.confirm/3` also
  # revokes, and its hook runs first, so an existing revocation means the token
  # is already spent rather than that something went wrong.
  defp revoke_token(changeset, token_resource, token, opts) do
    Changeset.after_action(changeset, fn _changeset, record ->
      case TokenResource.revoke(token_resource, token, opts) do
        :ok -> {:ok, record}
        {:error, %InvalidToken{type: :revocation}} -> {:ok, record}
        {:error, reason} -> {:error, reason}
      end
    end)
  end

  # `on_untrusted_email_match :confirm`: when the confirmed token carries a
  # pending provider identity link, create it once the user is confirmed.
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
