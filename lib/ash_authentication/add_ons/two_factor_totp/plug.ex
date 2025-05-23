defmodule AshAuthentication.AddOn.TwoFactorTotp.Plug do
  alias AshAuthentication.{AddOn.TwoFactorTotp, Errors.AuthenticationFailed, Strategy}
  alias Plug.Conn

  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  @spec verify(Conn.t(), TwoFactorTotp.t()) :: Conn.t()
  def verify(conn, strategy) do
    data = %{totp: conn.params["totp"], user: conn.assigns.current_user}

    case Strategy.action(strategy, :verify, data, []) do
      {:ok, user} ->
        store_authentication_result(conn, {:ok, user})

      {:error, reason} ->
        error =
          AuthenticationFailed.exception(
            strategy: strategy,
            caused_by: %{
              module: __MODULE__,
              strategy: strategy,
              action: :verify,
              message: "TOTP verification failed: #{inspect(reason)}"
            }
          )

        store_authentication_result(conn, {:error, error})
    end
  end
end
