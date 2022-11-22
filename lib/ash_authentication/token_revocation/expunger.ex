defmodule AshAuthentication.TokenRevocation.Expunger do
  @default_period_hrs 12

  @moduledoc """
  A `GenServer` which periodically removes expired token revocations.

  Scans all token revocation resources every #{@default_period_hrs} hours and removes
  any expired token revocations.

  You can change the expunger period by configuring it in your application
  environment:

  ```elixir
  config :ash_authentication, #{inspect(__MODULE__)},
    period_hrs: #{@default_period_hrs}
  ```

  This server is started automatically as part of the `:ash_authentication`
  supervision tree.
  """

  use GenServer
  alias AshAuthentication.TokenRevocation

  @doc false
  @spec start_link(any) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc false
  @impl true
  @spec init(any) :: {:ok, :timer.tref()}
  def init(_) do
    period =
      :ash_authentication
      |> Application.get_env(__MODULE__, [])
      |> Keyword.get(:period_hrs, @default_period_hrs)
      |> then(&(&1 * 60 * 60 * 1000))

    :timer.send_interval(period, :expunge)
  end

  @doc false
  @impl true
  def handle_info(:expunge, tref) do
    :code.all_loaded()
    |> Stream.map(&elem(&1, 0))
    |> Stream.filter(&function_exported?(&1, :spark_dsl_config, 0))
    |> Stream.filter(&(TokenRevocation in Spark.extensions(&1)))
    |> Enum.each(&TokenRevocation.expunge/1)

    {:noreply, tref}
  end
end
