# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.ApiKey do
  @moduledoc false
  alias Ash.Resource
  alias AshAuthentication.{Strategy, Strategy.ApiKey}

  @doc false
  @spec name(ApiKey.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(ApiKey.t()) :: [Strategy.phase()]
  def phases(_strategy), do: []

  @doc false
  def routes(_strategy), do: []

  @doc false
  def plug(_strategy, _phase, conn), do: conn

  @doc false
  def method_for_phase(_strategy, _phase), do: :get

  @doc false
  @spec actions(ApiKey.t()) :: [Strategy.action()]
  def actions(_strategy), do: [:sign_in]

  @doc false
  @spec action(ApiKey.t(), Strategy.action(), map, keyword) ::
          :ok | {:ok, Resource.record()} | {:error, any}
  def action(strategy, :sign_in, params, options),
    do: ApiKey.Actions.sign_in(strategy, params, options)

  @doc false
  @spec tokens_required?(ApiKey.t()) :: false
  def tokens_required?(_), do: false
end
