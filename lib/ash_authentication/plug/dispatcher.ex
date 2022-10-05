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
  def call(
        %{params: %{"subject_name" => subject_name, "provider" => provider}} = conn,
        {phase, routes, return_to}
      ) do
    conn =
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

    case conn do
      %{state: :sent} ->
        conn

      %{private: %{authentication_result: {:success, actor}}} ->
        return_to.handle_success(conn, actor, actor.__metadata__.token)

      _ ->
        return_to.handle_failure(conn)
    end
  end

  def call(conn, {_phase, _routes, return_to}), do: return_to.handle_failure(conn)
end
