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

  @doc false
  @impl true
  def run(input, _opts, context) do
    user = ActionInput.get_argument(input, :user)
    totp_code = ActionInput.get_argument(input, :code)

    load_opts =
      context
      |> Ash.Context.to_opts(lazy?: true, reuse_values?: true)

    with {:ok, strategy} <- Info.strategy_for_action(input.resource, input.action.name),
         {:ok, user} <-
           Ash.load(user, [strategy.secret_field, strategy.last_totp_at_field], load_opts) do
      secret = Map.get(user, strategy.secret_field)
      last_totp_at = datetime_to_unix(Map.get(user, strategy.last_totp_at_field))
      {:ok, NimbleTOTP.valid?(secret, totp_code, since: last_totp_at, period: strategy.period)}
    end
  end

  defp datetime_to_unix(nil), do: 0
  defp datetime_to_unix(%DateTime{} = dt), do: DateTime.to_unix(dt)
  defp datetime_to_unix(unix) when is_integer(unix), do: unix
end
