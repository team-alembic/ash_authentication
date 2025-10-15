# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AuditLogResource.Batcher do
  @moduledoc """
  A `GenServer` which batches up writes to the audit log to reduce write pressure in busy environments.

  Scans all audit log resources based on their configured write batching options.

  ```elixir
  defmodule MyApp.Accounts.AuditLog do
    use Ash.Resource,
      extensions: [AshAuthentication.AuditLogResource],
      domain: MyApp.Accounts


    audit_log do
      write_batching do
        enabled? true
        timeout :timer.seconds(10)
        max_size 100
      end
    end
  end
  ```

  This GenServer is started by the `AshAuthentication.Supervisor` which should be added to your app's supervision tree.
  """

  use GenServer
  alias AshAuthentication.AuditLogResource
  alias AshAuthentication.AuditLogResource.Info
  require Logger

  @doc """
  Queues an event for writing.
  """
  def enqueue(changeset), do: GenServer.cast(__MODULE__, {:enqueue, changeset})

  @doc """
  Flushes all queued events to the database immediately.

  Useful for testing to ensure all audit log entries are written before assertions.
  """
  def flush, do: GenServer.call(__MODULE__, :flush)

  @doc false
  @spec start_link(any) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc false
  @impl true
  @spec init(keyword) :: {:ok, map}
  def init(opts) do
    otp_app = Keyword.fetch!(opts, :otp_app)

    audit_configs =
      otp_app
      |> Spark.sparks(Ash.Resource)
      |> Stream.filter(&(AuditLogResource in Spark.extensions(&1)))
      |> Enum.reduce(%{}, fn resource, configs ->
        Map.put(configs, resource, %{
          timeout: Info.audit_log_write_batching_timeout!(resource),
          max_size: Info.audit_log_write_batching_max_size!(resource),
          action: Info.audit_log_write_action_name!(resource),
          domain: Info.audit_log_domain!(resource),
          queue: [],
          queue_size: 0,
          flush_timer: nil
        })
      end)

    if map_size(audit_configs) == 0 do
      :ignore
    else
      {:ok, audit_configs}
    end
  end

  @doc false
  @impl true
  def handle_info({:write_batch, resource}, state) do
    state =
      state
      |> Map.replace_lazy(resource, &write_batch(resource, %{&1 | flush_timer: nil}))

    {:noreply, state}
  end

  @doc false
  @impl true
  def handle_cast({:enqueue, changeset}, state) do
    state =
      state
      |> enqueue(changeset)
      |> maybe_write_batches()

    {:noreply, state}
  end

  @doc false
  @impl true
  def handle_call(:flush, _from, state) do
    state =
      state
      |> Enum.reduce(%{}, fn {resource, config}, configs ->
        config =
          if config.queue_size > 0 do
            if is_reference(config.flush_timer) do
              Process.cancel_timer(config.flush_timer)
            end

            write_batch(resource, %{config | flush_timer: nil})
          else
            config
          end

        Map.put(configs, resource, config)
      end)

    {:reply, :ok, state}
  end

  @doc false
  @impl true
  def terminate(_reason, state) do
    state
    |> Enum.filter(fn {_, %{queue_size: qs}} -> qs > 0 end)
    |> Enum.each(fn {resource, config} ->
      write_batch(resource, config)
    end)
  end

  defp enqueue(state, changeset) do
    Map.update!(state, changeset.resource, fn
      config when config.queue_size == 0 and config.queue == [] and config.timeout >= 0 ->
        timer = Process.send_after(self(), {:write_batch, changeset.resource}, config.timeout)

        %{
          config
          | queue: [changeset],
            queue_size: 1,
            flush_timer: timer
        }

      config ->
        %{config | queue: [changeset | config.queue], queue_size: config.queue_size + 1}
    end)
  end

  defp maybe_write_batches(state) do
    state
    |> Enum.reduce(%{}, fn
      {resource, config}, configs when config.queue_size >= config.max_size ->
        config =
          if is_reference(config.flush_timer) do
            Process.cancel_timer(config.flush_timer)
            write_batch(resource, %{config | flush_timer: nil})
          else
            write_batch(resource, config)
          end

        Map.put(configs, resource, config)

      {resource, config}, configs ->
        Map.put(configs, resource, config)
    end)
  end

  defp write_batch(resource, config) do
    bulk_result =
      config.queue
      |> Stream.map(& &1.attributes)
      |> Ash.bulk_create(resource, config.action,
        domain: config.domain,
        return_errors?: true,
        assume_casted?: true,
        context: %{private: %{ash_authentication?: true}}
      )

    if Enum.any?(bulk_result.errors) do
      Logger.error(fn ->
        """
        Errors occurred while writing audit logs to `#{inspect(resource)}`:

        #{inspect(bulk_result.errors)}
        """
      end)
    end

    %{config | queue: [], queue_size: 0}
  end
end
