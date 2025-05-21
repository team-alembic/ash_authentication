defmodule AshAuthentication.AddOn.TwoFactorTotp.Actions do
  alias Ash.Resource
  alias AshAuthentication.AddOn.TwoFactorTotp

  @spec verify(TwoFactorTotp.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def verify(strategy, params, opts \\ []) do
    params.user
    |> Ash.Changeset.for_update(strategy.verify_action_name, Map.take(params, [:totp]), opts)
    |> Ash.update(opts)
  end
end
