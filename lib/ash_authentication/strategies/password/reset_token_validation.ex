# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.ResetTokenValidation do
  @moduledoc """
  Validate that the token is a valid password reset request token.
  """

  use Ash.Resource.Validation
  alias Ash.{Changeset, Error.Changes.InvalidArgument, Resource.Validation}
  alias AshAuthentication.{Info, Jwt}

  @doc false
  @impl true
  @spec validate(Changeset.t(), keyword, Validation.Context.t()) :: :ok | {:error, Exception.t()}
  # The reset token names the user it was issued to in its `sub` claim. Without
  # comparing it to the record, a token issued to one user would reset the
  # password of whichever record the caller points the action at.
  def validate(changeset, _, context) do
    with {:ok, strategy} <- Info.strategy_for_action(changeset.resource, changeset.action.name),
         token when is_binary(token) <- Changeset.get_argument(changeset, :reset_token),
         {:ok, %{"act" => token_action, "sub" => subject}, _} <-
           Jwt.verify(token, changeset.resource, Ash.Context.to_opts(context)),
         true <- subject_matches?(subject, changeset.data),
         {:ok, resettable} <- Map.fetch(strategy, :resettable),
         true <- to_string(resettable.password_reset_action_name) == token_action do
      :ok
    else
      _ ->
        {:error, InvalidArgument.exception(field: :reset_token, message: "is not valid")}
    end
  end

  @impl true
  def atomic(changeset, opts, context) do
    validate(changeset, opts, context)
  end

  # AshAuthenticationPhoenix validates the reset form against an unsaved record
  # with no primary key. There is no row for the token to be bound to, and an
  # update without a primary key matches none; `Password.Actions.reset/3` always
  # runs the reset itself on the user the token names.
  defp subject_matches?(subject, %resource{} = record) when is_binary(subject) do
    if resource |> Ash.Resource.Info.primary_key() |> Enum.all?(&is_nil(Map.get(record, &1))) do
      true
    else
      Jwt.subject_matches_record?(subject, record)
    end
  end

  defp subject_matches?(_subject, _record), do: false
end
