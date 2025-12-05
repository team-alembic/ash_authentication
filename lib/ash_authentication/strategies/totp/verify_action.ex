defmodule AshAuthentication.Strategy.VerifyAction do
  use Ash.Resource.Actions.Implementation
  alias AshAuthentication.Info
  alias Ash.ActionInput

  @doc false
  @impl true
  def run(input, opts, context) do
    user = ActionInput.get_argument(input, :user)
    totp_code = ActionInput.get_argument(input, :code)

    load_opts =
      context
      |> Ash.Context.to_opts(lazy?: true, reuse_values?: true)

    with {:ok, strategy} <- Info.find_strategy(input, context, opts),
         {:ok, user} <-
           Ash.load(user, [strategy.secret_field, strategy.last_totp_at_field], load_opts) do
      secret = Map.get(user, strategy.secret_field)
      last_totp_at = Map.get(user, strategy.last_totp_at_field)
      {:ok, NimbleTOTP.valid?(secret, totp_code, since: last_totp_at, period: strategy.period)}
    end
  end
end
