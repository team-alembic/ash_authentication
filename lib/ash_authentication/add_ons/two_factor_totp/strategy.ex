defimpl AshAuthentication.Strategy, for: AshAuthentication.AddOn.TwoFactorTotp do
  @moduledoc false

  @doc false
  def name(strategy), do: strategy.name

  @doc false
  def phases(_), do: [:verify]

  @doc false
  def actions(_), do: []

  @doc false
  def routes(strategy) do
    subject_name = AshAuthentication.Info.authentication_subject_name!(strategy.resource)
    [{"/#{subject_name}/#{strategy.name}/verify", :verify}]
  end

  @doc false
  def method_for_phase(_, :verify), do: :post

  @doc false
  def tokens_required?(_), do: false
end
