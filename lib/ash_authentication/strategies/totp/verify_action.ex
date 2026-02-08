# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.VerifyAction do
  @moduledoc """
  Implementation of the TOTP verify action.

  This module is used as the `run` implementation for the verify action,
  which checks if a provided TOTP code is valid for a given user.
  """
  use Ash.Resource.Actions.Implementation
  alias Ash.ActionInput
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.Totp.Helpers

  @doc false
  @impl true
  def run(input, _opts, context) do
    user = ActionInput.get_argument(input, :user)
    totp_code = ActionInput.get_argument(input, :code)

    load_opts =
      context
      |> Ash.Context.to_opts(lazy?: true, reuse_values?: true)

    with :ok <- Helpers.validate_totp_code(totp_code),
         {:ok, strategy} <- Info.strategy_for_action(input.resource, input.action.name),
         {:ok, user} <-
           Ash.load(user, [strategy.read_secret_from, strategy.last_totp_at_field], load_opts) do
      secret = Map.get(user, strategy.read_secret_from)
      last_totp_at = Helpers.datetime_to_unix(Map.get(user, strategy.last_totp_at_field))
      {:ok, Helpers.valid_totp?(secret, totp_code, strategy, since: last_totp_at)}
    else
      {:error, :invalid_format} -> {:ok, false}
      other -> other
    end
  end
end
