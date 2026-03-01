defmodule AshAuthentication.Strategy.RecoveryCode.Plug do
  @moduledoc """
  Plugs for the recovery code strategy.

  Handles verify and generate requests for recovery code authentication.
  """

  alias AshAuthentication.{Info, Strategy, Strategy.RecoveryCode}
  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  @doc """
  Handle a recovery code verification request.

  The user is obtained from the connection's actor. On success, stores the
  verification result with metadata indicating a recovery code was used.
  The recovery code is deleted after successful verification.
  """
  @spec verify(Conn.t(), RecoveryCode.t()) :: Conn.t()
  def verify(conn, strategy) do
    user = get_actor(conn)
    params = subject_params(conn, strategy) |> Map.put("user", user)
    opts = opts(conn)
    result = Strategy.action(strategy, :verify, params, opts)

    case result do
      {:ok, user} ->
        user_with_metadata =
          user
          |> Ash.Resource.put_metadata(:recovery_code_used_at, DateTime.utc_now())

        store_authentication_result(conn, {:ok, user_with_metadata})

      error ->
        store_authentication_result(conn, error)
    end
  end

  @doc """
  Handle a recovery code generation request.

  The user is obtained from the connection's actor. On success, stores the
  list of plaintext recovery codes in the authentication result.
  """
  @spec generate(Conn.t(), RecoveryCode.t()) :: Conn.t()
  def generate(conn, strategy) do
    user = get_actor(conn)
    params = %{"user" => user}
    opts = opts(conn)
    result = Strategy.action(strategy, :generate, params, opts)
    store_authentication_result(conn, result)
  end

  defp subject_params(conn, strategy) do
    subject_name =
      strategy.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    Map.get(conn.params, subject_name, %{})
  end

  defp opts(conn) do
    [actor: get_actor(conn), tenant: get_tenant(conn), context: get_context(conn)]
    |> Enum.reject(&is_nil(elem(&1, 1)))
  end
end
