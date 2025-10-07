# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.RequestPasswordReset do
  @moduledoc """
  Requests a password reset.

  This implementation performs three jobs:
  1. looks up the user with the given action and field
  2. if a matching user is found:
    a. a reset token is generated
    b. and the password reset sender is invoked
  """
  use Ash.Resource.Actions.Implementation
  alias AshAuthentication.{Info, Strategy.Password}
  require Ash.Query
  require Logger

  @doc false
  @impl true
  def run(action_input, opts, context) do
    read_action = opts[:action]

    strategy = Info.strategy_for_action!(action_input.resource, action_input.action.name)

    if strategy.resettable && strategy.resettable.sender do
      identity_field = strategy.identity_field
      identity = Ash.ActionInput.get_argument(action_input, identity_field)
      select_for_senders = Info.authentication_select_for_senders!(action_input.resource)
      {sender, send_opts} = strategy.resettable.sender
      send_opts = Keyword.put(send_opts, :context, action_input.context)

      query_result =
        action_input.resource
        |> Ash.Query.new()
        |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
        |> Ash.Query.for_read(
          read_action,
          %{
            identity_field => identity
          },
          tenant: context.tenant
        )
        |> Ash.Query.ensure_selected(select_for_senders)
        |> Ash.read_one()

      with {:ok, user} when not is_nil(user) <- query_result,
           {:ok, token} <- Password.reset_token_for(strategy, user) do
        sender.send(user, token, Keyword.put(send_opts, :tenant, context.tenant))

        :ok
      else
        {:ok, nil} ->
          :ok

        :error ->
          Logger.warning("""
          Something went wrong generating a token during password reset
          for: #{inspect(action_input.resource)} `#{identity}`
          """)

        {:error, error} ->
          Logger.warning("""
          Something went wrong resetting password for #{inspect(action_input.resource)} `#{identity}`

          #{Exception.format(:error, error)}
          """)

          :ok
      end
    else
      :ok
    end
  end
end
