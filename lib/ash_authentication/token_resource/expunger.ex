defmodule AshAuthentication.TokenResource.Expunger do
  @moduledoc """
  A `GenServer` which periodically removes expired token revocations.

  Scans all token revocation resources based on their configured expunge
  interval and removes any expired records.

  ```elixir
  defmodule MyApp.Accounts.Token do
    use Ash.Resource,
      extensions: [AshAuthentication.TokenResource],
      domain: MyApp.Accounts

    token do
      expunge_interval 12
    end
  end
  ```

  This GenServer is started by the `AshAuthentication.Supervisor` which should
  be added to your app's supervision tree.
  """

  use GenServer
  alias AshAuthentication.{TokenResource, TokenResource.Actions, TokenResource.Info}

  @doc false
  @spec start_link(any) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc false
  @impl true
  @spec init(any) :: {:ok, map}
  def init(opts) do
    otp_app = Keyword.fetch!(opts, :otp_app)

    resource_states =
      otp_app
      |> Spark.sparks(Ash.Resource)
      |> Stream.filter(&(TokenResource in Spark.extensions(&1)))
      |> Enum.reduce(%{}, fn resource, resources ->
        state =
          resources
          |> Map.get(resource, %{interval: nil, timer: nil})
          |> maybe_update_timer(resource, interval_for(resource))

        Map.put(resources, resource, state)
      end)

    {:ok, %{otp_app: otp_app, resources: resource_states}}
  end

  @doc false
  @impl true
  @spec handle_info(any, map) :: {:noreply, map}
  def handle_info({:expunge, resource}, state) do
    Actions.expunge_expired(resource)

    resource_state =
      state.resources
      |> Map.get(resource)
      |> maybe_update_timer(resource, interval_for(resource))

    {:noreply, %{state | resources: Map.put(state.resources, resource, resource_state)}}
  end

  def handle_info(_, state), do: {:noreply, state}

  defp interval_for(resource) do
    Info.token_expunge_interval!(resource) * 60 * 60 * 1000
  end

  defp maybe_update_timer(state, resource, new_interval)
       when state.interval == new_interval and is_nil(state.timer) do
    {:ok, timer} = :timer.send_interval(new_interval, {:expunge, resource})
    %{state | timer: timer}
  end

  defp maybe_update_timer(state, _resource, new_interval) when state.interval == new_interval,
    do: state

  defp maybe_update_timer(state, resource, new_interval) when is_nil(state.timer) do
    {:ok, timer} = :timer.send_interval(new_interval, {:expunge, resource})
    %{state | interval: new_interval, timer: timer}
  end

  defp maybe_update_timer(state, resource, new_interval) do
    :timer.cancel(state.timer)
    {:ok, timer} = :timer.send_interval(new_interval, {:expunge, resource})
    %{state | interval: new_interval, timer: timer}
  end
end
