# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defimpl AshAuthentication.Strategy, for: AshAuthentication.AddOn.LogOutEverywhere do
  @moduledoc """
  Implementation of `AshAuthentication.Strategy` for
  `AshAuthentication.AddOn.LogOutEverywhere`.
  """

  alias Ash.ActionInput

  @doc false
  @impl true
  def name(strategy), do: strategy.name

  @doc false
  @impl true
  def phases(_), do: []

  @doc false
  @impl true
  def actions(_), do: [:log_out_everywhere]

  @doc false
  @impl true
  def method_for_phase(_, _), do: :get

  @doc false
  @impl true
  def routes(_), do: []

  @doc false
  @impl true
  def plug(_strategy, _, conn), do: conn

  @doc false
  @impl true
  def action(strategy, :log_out_everywhere, params, options) do
    strategy.resource
    |> ActionInput.new()
    |> ActionInput.set_context(%{private: %{ash_authentication?: true}})
    |> ActionInput.for_action(strategy.action_name, params)
    |> Ash.run_action(options)
  end

  @doc false
  @impl true
  def tokens_required?(_), do: true
end
