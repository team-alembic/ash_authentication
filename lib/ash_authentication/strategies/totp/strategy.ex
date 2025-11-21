defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.Totp do
  @moduledoc """
  Implementation of `AshAuthentication.Strategy` for `AshAuthentication.Strategy.Totp`.
  """
  alias AshAuthentication.{Info, Strategy, Strategy.Totp}
  alias Plug.Conn

  @doc false
  @spec name(Totp.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(Totp.t()) :: [atom]
  def phases(_strategy), do: [:verify]

  @doc false
  @spec actions(Totp.t()) :: [atom]
  def actions(_strategy), do: [:verify]

  @doc false
  @spec method_for_phase(Totp.t(), atom) :: Strategy.http_method()
  def method_for_phase(_strategy, :verify), do: :post

  @doc false
  @spec routes(Totp.t()) :: [Strategy.route()]
  def routes(strategy) do
    subject_name = Info.authentication_subject_name!(strategy.resource)
    path = "/#{subject_name}/#{strategy.name}"

    [{path, :verify}]
  end

  @doc false
  @spec plug(Totp.t(), atom, Conn.t()) :: Conn.t()
  def plug(strategy, :verify, conn), do: Totp.Plug.verify(conn, strategy)

  @doc false
  @spec action(Totp.t(), atom, map, keyword) :: {:ok, Resource.record()} | {:error, any}

  def action(strategy, :verify, params, options),
    do: Totp.Actions.verify(strategy, params, options)

  @doc false
  @spec tokens_required?(Totp.t()) :: false
  def tokens_required?(_strategy), do: false
end
