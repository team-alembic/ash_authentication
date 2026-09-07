# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.RequireConfirmedChange do
  @moduledoc """
  Refuse to register a user who has not confirmed.

  When the strategy sets `require_confirmed_with`, registration must not hand
  back a token for an account which has not completed confirmation. This change
  puts that check on the action itself, so it also applies when the action is
  invoked directly rather than through
  `AshAuthentication.Strategy.Password.Actions.register/3`. An API layer such as
  `AshGraphql` or `AshJsonApi` invokes the action directly.

  The check runs in an `after_transaction` hook rather than an `after_action`
  hook. An error from an `after_action` hook rolls the transaction back, which
  would stop registration from creating the account at all. The account must
  still be created so that the user can confirm it.

  See `AshAuthentication.Strategy.Password.RequireConfirmed`.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}
  alias AshAuthentication.{Info, Strategy.Password.RequireConfirmed}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, options, context) do
    case Info.find_strategy(changeset, context, options) do
      {:ok, %{require_confirmed_with: nil}} ->
        changeset

      {:ok, strategy} ->
        Changeset.after_transaction(changeset, &check_confirmed(&1, &2, strategy))

      :error ->
        changeset
    end
  end

  defp check_confirmed(changeset, {:ok, user}, strategy) do
    if RequireConfirmed.confirmed?(user, changeset, strategy) do
      {:ok, user}
    else
      {:error, RequireConfirmed.error(strategy)}
    end
  end

  defp check_confirmed(_changeset, result, _strategy), do: result
end
