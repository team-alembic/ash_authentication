defmodule AshAuthentication.Strategy.RecoveryCode.Plug do
  @moduledoc """
  Plugs for the recovery code strategy.

  Handles verify and generate requests for recovery code authentication.
  """

  alias AshAuthentication.{Errors, Info, Strategy, Strategy.RecoveryCode}
  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  @spec verify(Conn.t(), RecoveryCode.t()) :: Conn.t()
  def verify(conn, strategy) do
    case get_actor(conn) do
      nil ->
        store_authentication_result(conn, {:error, not_authenticated_error(strategy, :verify)})

      user ->
        params = subject_params(conn, strategy) |> Map.put("user", user)
        opts = opts(conn)

        case Strategy.action(strategy, :verify, params, opts) do
          {:ok, user} ->
            user_with_metadata =
              Ash.Resource.put_metadata(user, :recovery_code_used_at, DateTime.utc_now())

            store_authentication_result(conn, {:ok, user_with_metadata})

          error ->
            store_authentication_result(conn, error)
        end
    end
  end

  @spec generate(Conn.t(), RecoveryCode.t()) :: Conn.t()
  def generate(conn, strategy) do
    case get_actor(conn) do
      nil ->
        store_authentication_result(conn, {:error, not_authenticated_error(strategy, :generate)})

      user ->
        params = %{"user" => user}
        opts = opts(conn)
        result = Strategy.action(strategy, :generate, params, opts)
        store_authentication_result(conn, result)
    end
  end

  defp not_authenticated_error(strategy, action) do
    Errors.AuthenticationFailed.exception(
      strategy: strategy,
      caused_by: %{
        module: __MODULE__,
        strategy: strategy,
        action: action,
        message: "No authenticated user"
      }
    )
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
