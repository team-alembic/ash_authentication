# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defimpl AshAuthentication.Strategy, for: AshAuthentication.AddOn.AuditLog do
  @moduledoc """
  Implementation of `AshAuthentication.Strategy` for `AshAuthentication.AddOn.AuditLog`.
  """

  @doc false
  @impl true
  def name(strategy), do: strategy.name

  @doc false
  @impl true
  def phases(_), do: []

  @doc false
  @impl true
  def actions(_), do: []

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
  def action(strategy, _action, _params, _options) do
    {:error,
     AshAuthentication.Errors.AuthenticationFailed.exception(
       caused_by: %{message: "Spurious attempt to call an action on audit-log strategy"},
       strategy: strategy
     )}
  end

  @doc false
  @impl true
  def tokens_required?(_), do: false
end
