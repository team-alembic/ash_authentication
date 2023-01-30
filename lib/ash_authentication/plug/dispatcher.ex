defmodule AshAuthentication.Plug.Dispatcher do
  @moduledoc """
  Route requests and callbacks to the correct provider plugs.
  """

  @behaviour Plug
  alias AshAuthentication.Strategy
  alias Plug.Conn
  import AshAuthentication.Plug.Helpers, only: [get_authentication_result: 1]

  @type config :: {atom, Strategy.t(), module} | module

  @unsent ~w[unset set set_chunked set_file]a

  @doc false
  @impl true
  @spec init([config]) :: config
  def init([config]), do: config

  @doc """
  Send the request to the correct strategy and then return the result.
  """
  @impl true
  @spec call(Conn.t(), config | any) :: Conn.t()
  def call(conn, {phase, strategy, return_to}) do
    activity = {Strategy.name(strategy), phase}

    strategy
    |> Strategy.plug(phase, conn)
    |> get_authentication_result()
    |> case do
      {conn, _} when conn.state not in @unsent ->
        conn

      {conn, :ok} ->
        return_to.handle_success(conn, activity, nil, nil)

      {conn, {:ok, user}} when is_binary(user.__metadata__.token) ->
        return_to.handle_success(conn, activity, user, user.__metadata__.token)

      {conn, {:ok, user}} ->
        return_to.handle_success(conn, activity, user, nil)

      {conn, :error} ->
        return_to.handle_failure(conn, activity, nil)

      {conn, {:error, reason}} ->
        return_to.handle_failure(conn, activity, reason)

      conn when conn.state not in @unsent ->
        conn

      conn ->
        return_to.handle_failure(conn, activity, :no_authentication_result)
    end
  end

  def call(conn, return_to) do
    return_to.handle_failure(conn, {nil, nil}, :not_found)
  end
end
