defimpl AshAuthentication.Strategy, for: AshAuthentication.AddOn.TwoFactorTotp do
  @moduledoc false

  alias AshAuthentication.AddOn.TwoFactorTotp

  @doc false
  def name(strategy), do: strategy.name

  @doc false
  def phases(_), do: [:verify]

  @doc false
  def actions(_), do: [:setup, :verify]

  @doc false
  def routes(strategy) do
    subject_name = AshAuthentication.Info.authentication_subject_name!(strategy.resource)
    [{"/#{subject_name}/#{strategy.name}/verify", :verify}]
  end

  @doc false
  def method_for_phase(_, :verify), do: :post

  @doc false
  def tokens_required?(_), do: false

  @doc false
  def plug(strategy, :verify, conn) do
    TwoFactorTotp.Plug.verify(conn, strategy)
  end

  @doc false
  def action(strategy, :verify, params, options) do
    TwoFactorTotp.Actions.verify(strategy, params, options)
  end
end
