defmodule AshAuthentication.Plug.Dispatcher do
  @moduledoc """
  Route requests and callbacks to the correct provider plugs.
  """

  @behaviour Plug
  alias Plug.Conn

  @type config :: {:request | :callback, [AshAuthentication.Plug.authenticator_config()], module}

  @doc false
  @impl true
  @spec init([config]) :: config
  def init([config]), do: config

  @doc """
  Match the `subject_name` and `provider` of the incoming request to a provider and
  call the appropriate plug with the configuration.
  """
  @impl true
  @spec call(Conn.t(), config | any) :: Conn.t()
  def call(conn, {phase, routes, return_to}) do
    conn
    |> dispatch(phase, routes)
    |> return(return_to)
  end

  defp dispatch(
         %{params: %{"subject_name" => subject_name, "provider" => provider}} = conn,
         phase,
         routes
       ) do
    case Map.get(routes, {subject_name, provider}) do
      config when is_map(config) ->
        conn = Conn.put_private(conn, :authenticator, config)

        case phase do
          :request -> config.provider.request_plug(conn, [])
          :callback -> config.provider.callback_plug(conn, [])
        end

      _ ->
        conn
    end
  end

  defp dispatch(conn, _phase, _routes), do: conn

  defp return(%{state: :sent} = conn, _return_to), do: conn

  defp return(
         %{
           private: %{
             authentication_result: {:success, user},
             authenticator: %{resource: resource}
           }
         } = conn,
         return_to
       )
       when is_struct(user, resource),
       do: return_to.handle_success(conn, user, Map.get(user.__metadata__, :token))

  defp return(%{private: %{authentication_result: {:success, nil}}} = conn, return_to),
    do: return_to.handle_success(conn, nil, nil)

  defp return(%{private: %{authentication_result: {:failure, reason}}} = conn, return_to),
    do: return_to.handle_failure(conn, reason)

  defp return(conn, return_to), do: return_to.handle_failure(conn, nil)
end
