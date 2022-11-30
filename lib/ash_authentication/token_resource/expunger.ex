defmodule AshAuthentication.TokenResource.Expunger do
  @refresh_interval_hrs 1

  @moduledoc """
  A `GenServer` which periodically removes expired token revocations.

  Scans all token revocation resources based on their configured expunge
  interval and removes any expired records.

  ```elixir
  defmodule MyApp.Accounts.Token do
    use Ash.Resource,
      extensions: [AshAuthentication.TokenResource]

    token do
      api MyApp.Accounts
      expunge_interval 12
    end
  end
  ```

  This server is started automatically as part of the `:ash_authentication`
  supervision tree.

  Scans through all resources every #{if @refresh_interval_hrs == 1,
    do: "hour",
    else: "#{@refresh_interval_hrs} hours"} checking to make sure that no
  resources have been added or removed which need checking.  This allows us to
  support dynamically loaded and hot-reloaded modules.
  """

  use GenServer
  alias AshAuthentication.{TokenResource, TokenResource.Actions, TokenResource.Info}

  @doc false
  @spec start_link(any) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc false
  @impl true
  @spec init(any) :: {:ok, :timer.tref()}
  def init(_) do
    state =
      %{}
      |> refresh_state()

    {:ok, _} = :timer.send_interval(@refresh_interval_hrs * 60 * 60 * 1000, :refresh_state)

    {:ok, state}
  end

  @doc false
  @impl true
  @spec handle_info(any, map) :: {:noreply, map}
  def handle_info(:refresh_state, state) do
    state =
      state
      |> refresh_state()

    {:noreply, state}
  end

  def handle_info({:expunge, resource}, state) when :erlang.is_map_key(resource, state) do
    resource
    |> Actions.expunge_expired()

    {:noreply, state}
  end

  def handle_info(_, state), do: {:noreply, state}

  defp refresh_state(state) do
    :code.all_loaded()
    |> Stream.map(&elem(&1, 0))
    |> Stream.filter(&function_exported?(&1, :spark_dsl_config, 0))
    |> Stream.filter(&(TokenResource in Spark.extensions(&1)))
    |> Stream.map(&{&1, Info.token_expunge_interval!(&1) * 60 * 60 * 1000})
    |> Enum.reduce(state, fn {module, interval}, state ->
      case Map.get(state, module) do
        %{interval: ^interval, timer: timer} when not is_nil(timer) ->
          state

        %{timer: timer} when not is_nil(timer) ->
          :timer.cancel(timer)
          {:ok, timer} = :timer.send_interval(interval, {:expunge, module})
          Map.put(state, module, %{interval: interval, timer: timer})

        _ ->
          {:ok, timer} = :timer.send_interval(interval, {:expunge, module})
          Map.put(state, module, %{interval: interval, timer: timer})
      end
    end)
  end
end
