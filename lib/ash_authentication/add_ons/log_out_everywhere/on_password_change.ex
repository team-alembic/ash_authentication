# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.LogOutEverywhere.OnPasswordChange do
  @moduledoc """
  Logs a user out from everywhere by revoking all stored tokens.

  Given `hashed_password_field`, it does so only when the update changes that
  field. The check is made after the action has run, because
  `AshAuthentication.Strategy.Password.HashPasswordChange` sets the hash in a
  `before_action` hook: a `where` condition on the change would be evaluated
  before the hash exists, and would skip every non-atomic password change.
  Without the option, every update it is attached to logs the user out.
  """
  use Ash.Resource.Change

  alias AshAuthentication.{Info, Strategy}

  @impl true
  def change(changeset, opts, context) do
    Ash.Changeset.after_action(changeset, fn changeset, result ->
      if password_changed?(changeset, opts) do
        log_out_everywhere(changeset, result, context)
      else
        {:ok, result}
      end
    end)
  end

  defp password_changed?(changeset, opts) do
    case Keyword.fetch(opts, :hashed_password_field) do
      {:ok, field} -> Ash.Changeset.changing_attribute?(changeset, field)
      :error -> true
    end
  end

  defp log_out_everywhere(changeset, result, context) do
    strategy = Info.strategy!(changeset.resource, :log_out_everywhere)

    with :ok <-
           Strategy.action(
             strategy,
             :log_out_everywhere,
             %{user: result},
             Ash.Context.to_opts(context)
           ) do
      {:ok, result}
    end
  end

  @impl true
  def atomic(changeset, opts, context) do
    {:ok, change(changeset, opts, context)}
  end
end
