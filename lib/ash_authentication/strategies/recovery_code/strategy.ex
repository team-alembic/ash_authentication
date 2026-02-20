defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.RecoveryCode do
  @moduledoc """
  Implementation of `AshAuthentication.Strategy` for `AshAuthentication.Strategy.RecoveryCode`.
  """
  alias Ash.Resource
  alias AshAuthentication.{Info, Strategy, Strategy.RecoveryCode}
  alias Plug.Conn

  @doc false
  @spec name(RecoveryCode.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(RecoveryCode.t()) :: [atom]
  def phases(strategy) do
    [:verify]
    |> maybe_add(strategy.generate_enabled?, :generate)
  end

  @doc false
  @spec actions(RecoveryCode.t()) :: [atom]
  def actions(strategy) do
    [:verify]
    |> maybe_add(strategy.generate_enabled?, :generate)
  end

  @doc false
  @spec method_for_phase(RecoveryCode.t(), atom) :: Strategy.http_method()
  def method_for_phase(_strategy, :verify), do: :post
  def method_for_phase(_strategy, :generate), do: :post

  @doc false
  @spec routes(RecoveryCode.t()) :: [Strategy.route()]
  def routes(strategy) do
    subject_name = Info.authentication_subject_name!(strategy.resource)
    base = "/#{subject_name}/#{strategy.name}"

    [{"#{base}/verify", :verify}]
    |> maybe_add(strategy.generate_enabled?, {"#{base}/generate", :generate})
  end

  @doc false
  @spec plug(RecoveryCode.t(), atom, Conn.t()) :: Conn.t()
  def plug(strategy, :verify, conn), do: RecoveryCode.Plug.verify(conn, strategy)
  def plug(strategy, :generate, conn), do: RecoveryCode.Plug.generate(conn, strategy)

  @doc false
  @spec action(RecoveryCode.t(), atom, map, keyword) ::
          {:ok, Resource.record()} | {:error, any}
  def action(strategy, :verify, params, options),
    do: RecoveryCode.Actions.verify(strategy, params, options)

  def action(strategy, :generate, params, options),
    do: RecoveryCode.Actions.generate(strategy, params, options)

  @doc false
  @spec tokens_required?(RecoveryCode.t()) :: boolean
  def tokens_required?(_strategy), do: false

  defp maybe_add(list, true, item), do: list ++ [item]
  defp maybe_add(list, false, _item), do: list
end
