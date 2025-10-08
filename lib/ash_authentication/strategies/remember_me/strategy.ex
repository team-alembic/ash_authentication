# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.RememberMe do
  @moduledoc false
  alias Ash.Resource
  alias AshAuthentication.{Strategy, Strategy.RememberMe}
  alias Plug.Conn

  @doc false
  @spec name(RememberMe.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(RememberMe.t()) :: [Strategy.phase()]
  def phases(_strategy), do: []

  @doc false
  @spec actions(RememberMe.t()) :: [Strategy.action()]
  def actions(_strategy), do: []

  @doc false
  @spec method_for_phase(RememberMe.t(), atom) :: Strategy.http_method()
  def method_for_phase(_strategy, _request), do: :post

  @doc false
  @spec routes(RememberMe.t()) :: [Strategy.route()]
  def routes(_strategy), do: []

  @doc false
  @spec plug(RememberMe.t(), Strategy.phase(), Conn.t()) :: Conn.t()
  def plug(_strategy, _phase, conn), do: conn

  @doc false
  @spec action(RememberMe.t(), Strategy.action(), map, keyword) ::
          :ok | {:ok, Resource.record()} | {:error, any}
  def action(_strategy, _action, _params, _options),
    do: :ok

  @doc false
  @spec tokens_required?(RememberMe.t()) :: true
  def tokens_required?(_), do: true
end
