# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.Auditor do
  @moduledoc """
  Provides common audit logging behaviour for Ash actions.
  """

  alias __MODULE__
  alias AshAuthentication.AddOn.AuditLog.IpPrivacy
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
        changeset
        |> Auditor.tag_status_override_ref()
        |> Ash.Changeset.after_transaction(
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
        query
        |> Auditor.tag_status_override_ref()
        |> Ash.Query.after_transaction(
          &Auditor.after_transaction(&1, &2, opts[:strategy], context)
        )
      else
        query
      end
    end

    def prepare(input, opts, context) when is_struct(input, Ash.ActionInput) do
      tracked_actions = Auditor.get_tracked_actions(input.resource, opts[:strategy])

      if input.action.name in tracked_actions do
        input
        |> Auditor.tag_status_override_ref()
        |> Ash.ActionInput.after_transaction(
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
    persisted = Extension.get_persisted(resource, {:audit_log, strategy_name, :actions}) || []
    # Extract just the action names from the tuples
    Enum.map(persisted, fn
      {action_name, _strategy_name} -> action_name
      action_name -> action_name
    end)
  end

  @doc false
  @spec after_transaction(input, result, atom, map) :: result
  def after_transaction(input, result, strategy_name, context) do
    audit_strategy = AshAuthentication.Info.strategy!(input.resource, strategy_name)
    action_strategy = get_action_strategy(input, audit_strategy)

    status = determine_status(input, result)
    subject = extract_subject(result, input.resource)
    request = extract_request(context)
    identity = extract_identity(input, action_strategy)
    client_ip = extract_client_ip(request, audit_strategy)
    extra_data = build_extra_data(context, request, input, audit_strategy)

    params = %{
      strategy: action_strategy.name,
      subject: subject,
      identity: identity,
      client_ip: client_ip,
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

  defp get_action_strategy(input, audit_strategy) do
    case AshAuthentication.Info.strategy_for_action(input.resource, input.action.name) do
      {:ok, strategy} -> strategy
      :error -> audit_strategy
    end
  end

  @doc """
  Tag a query/changeset/action input with a unique reference used to bridge
  status overrides from downstream `after_action` callbacks into the audit
  log's `after_transaction` callback.

  Called automatically by the audit-log `Preparation` and `Change` modules;
  you should not need to call this directly.
  """
  @spec tag_status_override_ref(input) :: input
  def tag_status_override_ref(input) do
    ref = make_ref()

    put_private_context(input, :ash_authentication_audit_log_ref, ref)
  end

  @doc """
  Record a status override for the audit log entry that will be written for
  this action.

  Called from a preparation's `after_action` (or change's `after_action`) when
  the result of the action alone is not sufficient to determine whether the
  operation should be recorded as `:success` or `:failure` (for example,
  password reset and magic-link request actions return `:ok` regardless of
  whether the submitted identity resolved to a known user).

  If the audit-log add-on is not configured for this action, this call is a
  no-op.
  """
  @spec record_status_override(input, :success | :failure | :unknown) :: :ok
  def record_status_override(input, status)
      when status in [:success, :failure, :unknown] do
    case status_override_ref(input) do
      nil -> :ok
      ref -> Process.put({__MODULE__, :status_override, ref}, status)
    end

    :ok
  end

  defp determine_status(input, result) do
    case take_status_override(input) do
      status when status in [:success, :failure, :unknown] -> status
      _ -> determine_status_from_result(result)
    end
  end

  defp take_status_override(input) do
    case status_override_ref(input) do
      nil ->
        nil

      ref ->
        Process.delete({__MODULE__, :status_override, ref})
    end
  end

  defp status_override_ref(input) do
    input
    |> Map.get(:context, %{})
    |> Kernel.||(%{})
    |> Map.get(:private, %{})
    |> Map.get(:ash_authentication_audit_log_ref)
  end

  defp put_private_context(%Ash.Query{} = query, key, value) do
    Ash.Query.set_context(query, %{private: %{key => value}})
  end

  defp put_private_context(%Ash.Changeset{} = changeset, key, value) do
    Ash.Changeset.set_context(changeset, %{private: %{key => value}})
  end

  defp put_private_context(%Ash.ActionInput{} = input, key, value) do
    Ash.ActionInput.set_context(input, %{private: %{key => value}})
  end

  defp determine_status_from_result(result) do
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
  end

  defp extract_subject(result, resource) do
    case result do
      {:ok, user} when is_struct(user, resource) ->
        AshAuthentication.user_to_subject(user)

      # Read actions with get? true return {:ok, [user]}
      {:ok, [user]} when is_struct(user, resource) ->
        AshAuthentication.user_to_subject(user)

      _ ->
        nil
    end
  end

  defp extract_request(context) do
    context
    |> Map.get(:source_context, %{})
    |> Map.get(:ash_authentication_request, %{})
    |> Map.merge(Map.get(context, :ash_authentication_request, %{}))
  end

  defp extract_identity(input, action_strategy) do
    with identity_field when is_atom(identity_field) <-
           Map.get(action_strategy, :identity_field),
         value when not is_nil(value) <-
           get_argument_or_attribute(input, identity_field) do
      to_string(value)
    else
      _ -> nil
    end
  end

  defp get_argument_or_attribute(input, field) when is_struct(input, Ash.Changeset) do
    case Map.get(input.arguments, field) do
      nil -> Ash.Changeset.get_attribute(input, field)
      value -> value
    end
  end

  defp get_argument_or_attribute(input, field) do
    Map.get(input.arguments, field)
  end

  defp extract_client_ip(request, audit_strategy) do
    case Map.get(request, :remote_ip) do
      nil ->
        nil

      ip ->
        ip_privacy_mode = Map.get(audit_strategy, :ip_privacy_mode, :none)

        truncation_masks = %{
          ipv4: Map.get(audit_strategy, :ipv4_truncation_mask, 24),
          ipv6: Map.get(audit_strategy, :ipv6_truncation_mask, 48)
        }

        IpPrivacy.apply_privacy(ip, ip_privacy_mode, %{truncation_masks: truncation_masks})
    end
  end

  defp build_extra_data(context, request, input, audit_strategy) do
    # Apply IP privacy transformations to request data
    ip_privacy_mode = Map.get(audit_strategy, :ip_privacy_mode, :none)

    truncation_masks = %{
      ipv4: Map.get(audit_strategy, :ipv4_truncation_mask, 24),
      ipv6: Map.get(audit_strategy, :ipv6_truncation_mask, 48)
    }

    processed_request =
      IpPrivacy.apply_to_request(
        request,
        ip_privacy_mode,
        %{truncation_masks: truncation_masks}
      )

    context
    |> Map.take([:actor, :tenant])
    |> Map.update(:actor, nil, &serialise_actor/1)
    |> Map.put(:request, processed_request)
    |> Map.put(:params, get_params(input, audit_strategy))
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

  defp serialise_actor(nil), do: nil

  defp serialise_actor(actor) when is_struct(actor) do
    AshAuthentication.user_to_subject(actor)
  rescue
    _ -> inspect(actor)
  end

  defp serialise_actor(actor), do: actor
end
