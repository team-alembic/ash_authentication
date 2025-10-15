# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AuditLogResource.Expunger do
  @moduledoc """
  A `GenServer` which removes old audit log entries once they're no longer relevant.

  Scans all audit log resources based on their configured lifetime options.

  ```elixir
  defmodule MyApp.Accounts.AuditLog do
    use Ash.Resource,
      extensions: [AshAuthentication.AuditLogResource],
      domain: MyApp.Accounts

    audit_log do
      log_lifetime 90 # days
      expunge_interval 12 # hours
    end
  end
  ```

  This GenServer is started by the `AshAuthentication.Supervisor` which should be added to your app's supervision tree.
  """
  use GenServer
  alias AshAuthentication.AuditLogResource
  alias AshAuthentication.AuditLogResource.Info
  require Ash.Query

  @hibernate_timeout :timer.seconds(5)

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc false
  @impl true
  def init(opts) do
    opts
    |> Keyword.fetch!(:otp_app)
    |> Spark.sparks(Ash.Resource)
    |> Stream.filter(&(AuditLogResource in Spark.extensions(&1)))
    |> Enum.reduce([], fn resource, configs ->
      with {:ok, lifetime_days} when is_integer(lifetime_days) and lifetime_days > 0 <-
             Info.audit_log_log_lifetime(resource),
           {:ok, sweep_hrs} <- Info.audit_log_expunge_interval(resource),
           {:ok, action_name} <- Info.audit_log_destroy_action_name(resource),
           {:ok, logged_at} <- Info.audit_log_attributes_logged_at(resource) do
        timer = Process.send_after(self(), {:expunge, resource}, :timer.hours(sweep_hrs))

        config = %{
          lifetime: lifetime_days,
          interval: sweep_hrs,
          resource: resource,
          action_name: action_name,
          timer: timer,
          logged_at: logged_at
        }

        [config | configs]
      else
        _ -> configs
      end
    end)
    |> case do
      [] -> :ignore
      configs -> {:ok, Map.new(configs, &{&1.resource, &1}), @hibernate_timeout}
    end
  end

  @doc false
  @impl true
  def handle_info({:expunge, resource}, state) do
    state
    |> Map.get(resource)
    |> case do
      nil ->
        {:noreply, state, :hibernate}

      config ->
        logged_at = config.logged_at
        lifetime = config.lifetime

        import Ash.Expr

        resource
        |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
        |> Ash.Query.filter(^ref(logged_at) <= ago(^lifetime, :day))
        |> Ash.bulk_destroy(config.action_name, %{}, authorize?: false)

        timer = Process.send_after(self(), {:expunge, resource}, :timer.hours(config.interval))

        state = Map.put(state, resource, %{config | timer: timer})

        {:noreply, state, @hibernate_timeout}
    end
  end

  def handle_info(:timeout, state), do: {:noreply, state, :hibernate}
end
