# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defimpl AshAuthentication.Strategy, for: AshAuthentication.AddOn.Confirmation do
  @moduledoc """
  Implementation of `AshAuthentication.Strategy` for
  `AshAuthentication.AddOn.Confirmation`.
  """

  alias Ash.Resource
  alias AshAuthentication.{Info, Strategy, AddOn.Confirmation}
  alias Plug.Conn

  @typedoc "The request phases supposed by this strategy"
  @type phase :: :accept | :confirm

  @typedoc "The actions supported by this strategy"
  @type action :: :confirm

  @doc false
  @spec name(Confirmation.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(Confirmation.t()) :: [phase]
  def phases(strategy) when strategy.require_interaction?, do: [:accept, :confirm]
  def phases(_strategy), do: [:confirm]

  @doc false
  @spec actions(Confirmation.t()) :: [action]
  def actions(_), do: [:confirm]

  @doc false
  @spec method_for_phase(Confirmation.t(), phase) :: Strategy.http_method()
  def method_for_phase(strategy, :confirm) when strategy.require_interaction?, do: :post

  def method_for_phase(_strategy, _phase), do: :get

  @doc false
  @spec routes(Confirmation.t()) :: [Strategy.route()]
  def routes(strategy) do
    subject_name = Info.authentication_subject_name!(strategy.resource)
    path = "/#{subject_name}/#{strategy.name}"

    if strategy.require_interaction? do
      [{path, :confirm}, {path, :accept}]
    else
      [{path, :confirm}]
    end
  end

  @doc false
  @spec plug(Confirmation.t(), phase, Conn.t()) :: Conn.t()
  def plug(strategy, :confirm, conn), do: Confirmation.Plug.confirm(conn, strategy)
  def plug(strategy, :accept, conn), do: Confirmation.Plug.accept(conn, strategy)

  @doc false
  @spec action(Confirmation.t(), action, map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def action(strategy, :confirm, params, options),
    do: Confirmation.Actions.confirm(strategy, params, options)

  @doc false
  @spec tokens_required?(Confirmation.t()) :: true
  def tokens_required?(_), do: true
end
