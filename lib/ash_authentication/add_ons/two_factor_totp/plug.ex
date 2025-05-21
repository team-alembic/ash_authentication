defmodule AshAuthentication.AddOn.TwoFactorTotp.Plug do
  alias AshAuthentication.{AddOn.TwoFactorTotp, Strategy}
  alias Plug.Conn

  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  @spec verify(Conn.t(), TwoFactorTotp.t()) :: Conn.t()
  def verify(conn, strategy) do
    # TODO: will the assign always be `current_user`?
    data = %{totp: conn.params["totp"], user: conn.assigns.current_user}
    result = Strategy.action(strategy, :verify, data, [])
    # TODO: Error handling, wrap in AuthenticationFailed
    store_authentication_result(conn, result)
  end
end
