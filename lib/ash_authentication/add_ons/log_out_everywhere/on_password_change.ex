# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.LogOutEverywhere.OnPasswordChange do
  @moduledoc "Logs a user out from everywhere by revoking all stored tokens."
  use Ash.Resource.Change

  alias AshAuthentication.{Info, Strategy}

  @impl true
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, fn changeset, result ->
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
    end)
  end

  @impl true
  def atomic(changeset, opts, context) do
    {:ok, change(changeset, opts, context)}
  end
end
