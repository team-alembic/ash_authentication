# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.Auditor do
  @moduledoc """
  Provides common audit logging behaviour for Ash actions.
  """

  alias __MODULE__
  alias Spark.Dsl.Extension
  require Logger

  @type input :: Ash.ActionInput.t() | Ash.Changeset.t() | Ash.Query.t()
  @type result :: {:ok, Ash.Resource.record()} | {:ok, [Ash.Resource.record()]} | {:error, any()}

  defmodule Change do
    @moduledoc "Implements the `Ash.Resource.Change` behaviour for audit logging"
    use Ash.Resource.Change

    @doc false
    @impl true
    def change(changeset, opts, context) do
      tracked_actions = Auditor.get_tracked_actions(changeset.resource, opts[:strategy])

      if changeset.action.name in tracked_actions do
        Ash.Changeset.after_transaction(
          changeset,
          &Auditor.after_transaction(&1, &2, opts[:strategy], context)
        )
      else
        changeset
      end
    end

    @doc false
    @impl true
    def atomic(changeset, opts, context), do: {:ok, change(changeset, opts, context)}
  end

  defmodule Preparation do
    @moduledoc "Implements the `Ash.Resource.Preparation` behaviour for audit logging"
    use Ash.Resource.Preparation

    @doc false
    @impl true
    def prepare(query, opts, context) when is_struct(query, Ash.Query) do
      tracked_actions = Auditor.get_tracked_actions(query.resource, opts[:strategy])

      if query.action.name in tracked_actions do
        Ash.Query.after_transaction(
          query,
          &Auditor.after_transaction(&1, &2, opts[:strategy], context)
        )
      else
        query
      end
    end

    def prepare(input, opts, context) when is_struct(input, Ash.ActionInput) do
      tracked_actions = Auditor.get_tracked_actions(input.resource, opts[:strategy])

      if input.action.name in tracked_actions do
        Ash.ActionInput.after_transaction(
          input,
          &Auditor.after_transaction(&1, &2, opts[:strategy], context)
        )
      else
        input
      end
    end

    @doc false
    @impl true
    def supports(_opts), do: [Ash.Query, Ash.ActionInput]
  end

  @doc false
  @spec get_tracked_actions(Ash.Resource.t(), atom) :: [atom]
  def get_tracked_actions(resource, strategy_name) do
    Extension.get_persisted(resource, {:audit_log, strategy_name, :actions}) || []
  end

  @doc false
  @spec after_transaction(input, result, atom, map) :: result
  def after_transaction(input, result, strategy_name, context) do
    audit_strategy = AshAuthentication.Info.strategy!(input.resource, strategy_name)

    action_strategy =
      AshAuthentication.Info.strategy_for_action!(input.resource, input.action.name)

    status =
      case result do
        :ok ->
          :success

        {:ok, _} ->
          :success

        {:ok, _, _} ->
          :success

        {:error, _} ->
          :failure

        :error ->
          :failure

        other ->
          Logger.warning(
            "Auditor after_transaction hook received unexpected result: `#{inspect(other)}`"
          )

          :unknown
      end

    subject =
      case result do
        {:ok, user} when is_struct(user, input.resource) ->
          AshAuthentication.user_to_subject(user)

        _ ->
          nil
      end

    request =
      context
      |> Map.get(:source_context, %{})
      |> Map.get(:ash_authentication_request, %{})
      |> Map.merge(Map.get(context, :ash_authentication_request, %{}))

    extra_data =
      context
      |> Map.take([:actor, :tenant])
      |> Map.put(:request, request)
      |> Map.put(:params, get_params(input, audit_strategy))

    params = %{
      strategy: action_strategy.name,
      subject: subject,
      audit_log: audit_strategy.name,
      logged_at: DateTime.utc_now(),
      action_name: input.action.name,
      status: status,
      extra_data: extra_data,
      resource: input.resource
    }

    with {:error, reason} <-
           AshAuthentication.AuditLogResource.log_activity(audit_strategy, params) do
      Logger.error(fn ->
        """
        Error writing audit log: #{inspect(reason)}
        """
      end)
    end

    result
  end

  defp get_params(input, audit_strategy) do
    argument_names =
      Extension.get_persisted(
        audit_strategy.resource,
        {:audit_log, audit_strategy.name, input.action.name, :arguments}
      ) || []

    attribute_names =
      Extension.get_persisted(
        audit_strategy.resource,
        {:audit_log, audit_strategy.name, input.action.name, :attributes}
      ) || []

    arguments = get_named_arguments(input, argument_names)
    attributes = get_named_attributes(input, attribute_names)

    attributes
    |> Map.merge(arguments)
  end

  defp get_named_arguments(input, argument_names), do: Map.take(input.arguments, argument_names)

  defp get_named_attributes(_input, []), do: %{}

  defp get_named_attributes(input, attribute_names) when is_struct(input, Ash.Changeset),
    do: Map.new(attribute_names, &{&1, Ash.Changeset.get_attribute(input, &1)})

  defp get_named_attributes(_input, _attribute_names), do: %{}
end
