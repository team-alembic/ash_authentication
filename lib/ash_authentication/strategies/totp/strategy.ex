# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.Totp do
  @moduledoc """
  Implementation of `AshAuthentication.Strategy` for `AshAuthentication.Strategy.Totp`.
  """
  alias Ash.Resource
  alias AshAuthentication.{Info, Strategy, Strategy.Totp}
  alias Plug.Conn

  @doc false
  @spec name(Totp.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(Totp.t()) :: [atom]
  def phases(strategy) do
    []
    |> maybe_add(strategy.setup_enabled?, :setup)
    |> maybe_add(strategy.confirm_setup_enabled?, :confirm_setup)
    |> maybe_add(strategy.sign_in_enabled?, :sign_in)
    |> maybe_add(strategy.verify_enabled?, :verify)
  end

  @doc false
  @spec actions(Totp.t()) :: [atom]
  def actions(strategy) do
    []
    |> maybe_add(strategy.setup_enabled?, :setup)
    |> maybe_add(strategy.confirm_setup_enabled?, :confirm_setup)
    |> maybe_add(strategy.sign_in_enabled?, :sign_in)
    |> maybe_add(strategy.verify_enabled?, :verify)
  end

  @doc false
  @spec method_for_phase(Totp.t(), atom) :: Strategy.http_method()
  def method_for_phase(_strategy, :confirm_setup), do: :post
  def method_for_phase(_strategy, :setup), do: :post
  def method_for_phase(_strategy, :sign_in), do: :post
  def method_for_phase(_strategy, :verify), do: :post

  @doc false
  @spec routes(Totp.t()) :: [Strategy.route()]
  def routes(strategy) do
    subject_name = Info.authentication_subject_name!(strategy.resource)
    base = "/#{subject_name}/#{strategy.name}"

    []
    |> maybe_add(strategy.setup_enabled?, {"#{base}/setup", :setup})
    |> maybe_add(strategy.confirm_setup_enabled?, {"#{base}/confirm_setup", :confirm_setup})
    |> maybe_add(strategy.sign_in_enabled?, {"#{base}/sign_in", :sign_in})
    |> maybe_add(strategy.verify_enabled?, {"#{base}/verify", :verify})
  end

  @doc false
  @spec plug(Totp.t(), atom, Conn.t()) :: Conn.t()
  def plug(strategy, :confirm_setup, conn), do: Totp.Plug.confirm_setup(conn, strategy)
  def plug(strategy, :setup, conn), do: Totp.Plug.setup(conn, strategy)
  def plug(strategy, :sign_in, conn), do: Totp.Plug.sign_in(conn, strategy)
  def plug(strategy, :verify, conn), do: Totp.Plug.verify(conn, strategy)

  @doc false
  @spec action(Totp.t(), atom, map, keyword) ::
          {:ok, Resource.record()} | {:ok, boolean} | {:error, any}
  def action(strategy, :confirm_setup, params, options),
    do: Totp.Actions.confirm_setup(strategy, params, options)

  def action(strategy, :setup, params, options),
    do: Totp.Actions.setup(strategy, params, options)

  def action(strategy, :sign_in, params, options),
    do: Totp.Actions.sign_in(strategy, params, options)

  def action(strategy, :verify, params, options),
    do: Totp.Actions.verify(strategy, params, options)

  @doc false
  @spec tokens_required?(Totp.t()) :: boolean
  def tokens_required?(strategy), do: strategy.confirm_setup_enabled?

  defp maybe_add(list, true, item), do: list ++ [item]
  defp maybe_add(list, false, _item), do: list
end
