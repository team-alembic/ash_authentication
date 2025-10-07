# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.MagicLink.Request do
  @moduledoc """
  Requests a magic link for the given identity field.
  """
  use Ash.Resource.Actions.Implementation
  alias Ash.{ActionInput, Query}
  alias AshAuthentication.{Info, Strategy.MagicLink}
  # require Ash.Query

  @doc false
  @impl true
  def run(input, _opts, context) do
    strategy = Info.strategy_for_action!(input.resource, input.action.name)
    identity = ActionInput.get_argument(input, strategy.identity_field)
    context_opts = Ash.Context.to_opts(context)

    input.resource
    |> Query.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Ash.Query.for_read(
      strategy.lookup_action_name,
      %{strategy.identity_field => identity},
      context_opts
    )
    |> Ash.read_one()
    |> case do
      {:error, error} ->
        {:error, error}

      {:ok, nil} ->
        with true <- strategy.registration_enabled?,
             {sender, send_opts} <- strategy.sender,
             {:ok, token} <-
               MagicLink.request_token_for_identity(strategy, identity, context_opts, context) do
          build_opts =
            Keyword.merge(send_opts,
              tenant: context.tenant,
              source_context: context.source_context
            )

          sender.send(to_string(identity), token, build_opts)

          :ok
        else
          _ ->
            :ok
        end

      {:ok, user} ->
        with {sender, send_opts} <- strategy.sender,
             {:ok, token} <-
               MagicLink.request_token_for_identity(strategy, identity, context_opts, context) do
          build_opts =
            Keyword.merge(send_opts,
              tenant: context.tenant,
              source_context: context.source_context
            )

          sender.send(user, token, build_opts)

          :ok
        else
          _ ->
            :ok
        end
    end
  end
end
