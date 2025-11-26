defmodule AshAuthentication.Strategy.Totp.GenerateSecretChange do
  use Ash.Resource.Change

  alias AshAuthentication.Info
  alias Ash.Changeset
  alias Ash.Error.Framework.AssumptionFailed

  @doc false
  @impl true
  def change(changeset, _context, _opts) do
    case Info.strategy_for_action(changeset.resource, changeset.action.name) do
      {:ok, strategy} ->
        do_change(changeset, strategy)

      :error ->
        raise AssumptionFailed,
          message: "Action does not correlate with an authentication strategy"
    end
  end

  defp do_change(changeset, strategy) do
    changeset
    |> Changeset.set_context(%{private: %{ash_authentication?: true}})
    |> Changeset.before_action(fn changeset ->
      changeset
      |> Changeset.force_change_attribute(
        strategy.secret_field,
        NimbleTOTP.secret(strategy.secret_length)
      )
    end)
  end
end
