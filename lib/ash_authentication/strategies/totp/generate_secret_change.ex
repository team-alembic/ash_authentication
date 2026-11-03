# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.GenerateSecretChange do
  @moduledoc """
  Generates a new TOTP secret for a user.

  This change is used by the setup action to generate a cryptographically
  secure random secret for TOTP authentication.
  """
  use Ash.Resource.Change

  alias Ash.Changeset
  alias Ash.Error.Framework.AssumptionFailed
  alias AshAuthentication.Info

  @doc false
  @impl true
  def change(changeset, _context, _opts) do
    case Info.strategy_for_action(changeset.resource, changeset.action.name) do
      {:ok, strategy} ->
        do_change(changeset, strategy)

      :error ->
        raise AssumptionFailed,
          message: "Action does not correlate with an authentication strategy"
    end
  end

  # This change does not mark the changeset as an AshAuthentication
  # interaction. `AshAuthentication.Strategy.Totp.Actions.setup/3` does, for
  # the record it was given; a direct call to the action is left to the
  # resource's policies.
  defp do_change(changeset, strategy) do
    changeset
    |> Changeset.before_action(fn changeset ->
      changeset
      |> Changeset.force_change_attribute(
        strategy.secret_field,
        NimbleTOTP.secret(strategy.secret_length)
      )
    end)
  end
end
