defmodule AshAuthentication.Confirmation.Transformer do
  @moduledoc """
  The Confirmation transformer.

  Scans the resource and checks that all the fields and actions needed are present.
  """
  use Spark.Dsl.Transformer

  alias AshAuthentication.Confirmation.{
    ConfirmationHookChange,
    ConfirmChange,
    Info
  }

  alias Ash.{Resource, Type}
  alias AshAuthentication.{GenerateTokenChange, Sender}
  alias Spark.{Dsl.Transformer, Error.DslError}

  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @impl true
  @spec transform(map) ::
          :ok
          | {:ok, map()}
          | {:error, term()}
          | {:warn, map(), String.t() | [String.t()]}
          | :halt
  def transform(dsl_state) do
    with :ok <- validate_extension(dsl_state, AshAuthentication),
         :ok <- validate_token_generation_enabled(dsl_state),
         {:ok, {sender, _opts}} <- Info.sender(dsl_state),
         :ok <- validate_behaviour(sender, Sender),
         :ok <- validate_monitor_fields(dsl_state),
         {:ok, action_name} <- Info.confirm_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(dsl_state, action_name, &build_confirm_action(&1, action_name)),
         :ok <- validate_confirm_action(dsl_state, action_name),
         {:ok, confirmed_at} <- Info.confirmed_at_field(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_attribute(
             dsl_state,
             confirmed_at,
             &build_confirmed_at_attribute(&1, confirmed_at)
           ),
         :ok <- validate_confirmed_at_attribute(dsl_state),
         {:ok, dsl_state} <- maybe_build_change(dsl_state, ConfirmationHookChange) do
      authentication =
        Transformer.get_persisted(dsl_state, :authentication)
        |> Map.update(
          :providers,
          [AshAuthentication.Confirmation],
          &[AshAuthentication.Confirmation | &1]
        )

      dsl_state =
        dsl_state
        |> Transformer.persist(:authentication, authentication)

      {:ok, dsl_state}
    else
      :error -> {:error, "Configuration error"}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc false
  @impl true
  @spec after?(module) :: boolean
  def after?(AshAuthentication.Transformer), do: true
  def after?(_), do: false

  @doc false
  @impl true
  @spec before?(module) :: boolean
  def before?(Resource.Transformers.DefaultAccept), do: true
  def before?(_), do: false

  defp validate_confirmed_at_attribute(dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, field_name} <- Info.confirmed_at_field(dsl_state),
         {:ok, attribute} <- find_attribute(dsl_state, field_name),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :type, [Type.UtcDatetimeUsec]) do
      :ok
    else
      :error ->
        {:error,
         DslError.exception(
           path: [:confirmation],
           message: "The `confirmed_at_field` option must be set."
         )}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp validate_monitor_fields(dsl_state) do
    case Info.monitor_fields(dsl_state) do
      {:ok, [_ | _] = fields} ->
        Enum.reduce_while(fields, :ok, &validate_monitored_field_reducer(dsl_state, &1, &2))

      _ ->
        {:error,
         DslError.exception(
           path: [:confirmation],
           message:
             "The `AshAuthentication.Confirmation` extension requires at least one monitored field to be configured."
         )}
    end
  end

  defp validate_monitored_field_reducer(dsl_state, field, _) do
    case validate_monitored_field(dsl_state, field) do
      :ok -> {:cont, :ok}
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp validate_monitored_field(dsl_state, field) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      maybe_validate_eager_checking(dsl_state, field, resource)
    end
  end

  defp maybe_validate_eager_checking(dsl_state, field, resource) do
    if Info.inhibit_updates?(dsl_state) do
      dsl_state
      |> Resource.Info.identities()
      |> Enum.find(&(&1.keys == [field]))
      |> case do
        %{eager_check_with: nil} ->
          {:error,
           DslError.exception(
             path: [:identities, :identity],
             message:
               "The attribute `#{inspect(field)}` on the resource `#{inspect(resource)}` needs the `eager_check_with` property set so that inhibited changes are still validated."
           )}

        _ ->
          :ok
      end
    else
      :ok
    end
  end

  defp build_confirm_action(dsl_state, action_name) do
    with {:ok, fields} <- Info.monitor_fields(dsl_state) do
      arguments = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :update], :argument,
          name: :confirm,
          type: Type.String,
          allow_nil?: false
        )
      ]

      changes = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :update], :change,
          change: ConfirmChange
        ),
        Transformer.build_entity!(Resource.Dsl, [:actions, :update], :change,
          change: GenerateTokenChange
        )
      ]

      Transformer.build_entity(Resource.Dsl, [:actions], :update,
        name: action_name,
        accept: fields,
        arguments: arguments,
        changes: changes
      )
    end
  end

  defp maybe_build_attribute(dsl_state, attribute_name, builder) do
    with {:error, _} <- find_attribute(dsl_state, attribute_name),
         {:ok, attribute} <- builder.(dsl_state) do
      {:ok, Transformer.add_entity(dsl_state, [:attributes], attribute)}
    else
      {:ok, attribute} when is_struct(attribute, Resource.Attribute) -> {:ok, dsl_state}
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_confirmed_at_attribute(_dsl_state, attribute_name) do
    Transformer.build_entity(Resource.Dsl, [:attributes], :attribute,
      name: attribute_name,
      type: Type.UtcDatetimeUsec,
      allow_nil?: true,
      writable?: true
    )
  end

  defp maybe_build_change(dsl_state, change_module) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         changes <- Resource.Info.changes(resource),
         false <- change_module in changes,
         {:ok, change} <-
           Transformer.build_entity(Resource.Dsl, [:changes], :change, change: change_module) do
      {:ok, Transformer.add_entity(dsl_state, [:changes], change)}
    else
      true -> {:ok, dsl_state}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_confirm_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_action_has_change(action, ConfirmChange),
         :ok <- validate_action_argument_option(action, :confirm, :type, [Type.String]) do
      validate_action_argument_option(action, :confirm, :allow_nil?, [false])
    end
  end
end
