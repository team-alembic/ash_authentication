defmodule AshAuthentication.AddOn.Confirmation.Transformer do
  @moduledoc """
  DSL transformer for confirmation add-on.

  Ensures that there is only ever one present and that it is correctly
  configured.
  """

  alias Ash.{Resource, Type}
  alias AshAuthentication.{AddOn.Confirmation, GenerateTokenChange}
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute
  import AshAuthentication.Strategy.Custom.Helpers

  @doc false
  @spec transform(Confirmation.t(), map) ::
          {:ok, Confirmation.t() | map} | {:error, Exception.t()}
  def transform(strategy, dsl_state) do
    with :ok <-
           validate_token_generation_enabled(
             dsl_state,
             "Token generation must be enabled for password resets to work."
           ),
         :ok <- validate_monitor_fields(dsl_state, strategy),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             strategy.confirm_action_name,
             &build_confirm_action(&1, strategy)
           ),
         :ok <- validate_confirm_action(dsl_state, strategy),
         {:ok, dsl_state} <-
           maybe_build_attribute(
             dsl_state,
             strategy.confirmed_at_field,
             &build_confirmed_at_attribute(&1, strategy)
           ),
         :ok <- validate_confirmed_at_attribute(dsl_state, strategy),
         {:ok, dsl_state} <-
           maybe_build_change(
             dsl_state,
             {Confirmation.ConfirmationHookChange, strategy_name: strategy.name}
           ),
         {:ok, resource} <- persisted_option(dsl_state, :module) do
      strategy = %{strategy | resource: resource}

      dsl_state =
        dsl_state
        |> then(&register_strategy_actions([strategy.confirm_action_name], &1, strategy))
        |> put_add_on(strategy)

      {:ok, dsl_state}
    else
      {:error, reason} when is_binary(reason) ->
        {:error,
         DslError.exception(path: [:authentication, :add_ons, :confirmation], message: reason)}

      {:error, reason} ->
        {:error, reason}

      :error ->
        {:error,
         DslError.exception(
           path: [:authentication, :add_ons, :confirmation],
           message: "Configuration error"
         )}
    end
  end

  defp validate_monitor_fields(_dsl_state, %{monitor_fields: []}),
    do:
      {:error,
       DslError.exception(
         path: [:authentication, :add_ons, :confirmation],
         message: "You should be monitoring at least one field"
       )}

  defp validate_monitor_fields(dsl_state, strategy) do
    Enum.reduce_while(strategy.monitor_fields, :ok, fn field, :ok ->
      with {:ok, resource} <- persisted_option(dsl_state, :module),
           {:ok, attribute} <- find_attribute(dsl_state, field),
           :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
           :ok <- validate_attribute_option(attribute, resource, :public?, [true]),
           :ok <- maybe_validate_eager_checking(dsl_state, strategy, field, resource) do
        {:cont, :ok}
      else
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp maybe_validate_eager_checking(_dsl_state, %{inhibit_updates?: false}, _, _), do: :ok

  defp maybe_validate_eager_checking(dsl_state, _strategy, field, resource) do
    dsl_state
    |> Resource.Info.identities()
    |> Enum.find(&(&1.keys == [field]))
    |> case do
      %{name: name, eager_check_with: nil} ->
        {:error,
         DslError.exception(
           path: [:identities, :identity],
           message:
             "The #{name} identity on the resource `#{inspect(resource)}` needs the `eager_check_with` property set so that inhibited changes are still validated."
         )}

      _ ->
        :ok
    end
  end

  defp build_confirm_action(_dsl_state, strategy) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :update], :argument,
        name: :confirm,
        type: Type.String,
        allow_nil?: false,
        public?: true
      )
    ]

    changes = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :update], :change,
        change: Confirmation.ConfirmChange
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :update], :change,
        change: GenerateTokenChange
      )
    ]

    metadata = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :update], :metadata,
        name: :token,
        type: :string,
        allow_nil?: false
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :update,
      name: strategy.confirm_action_name,
      accept: strategy.monitor_fields,
      arguments: arguments,
      metadata: metadata,
      changes: changes,
      require_atomic?: false
    )
  end

  defp validate_confirm_action(dsl_state, strategy) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.confirm_action_name),
         :ok <- validate_action_has_change(action, Confirmation.ConfirmChange),
         :ok <- validate_action_argument_option(action, :confirm, :allow_nil?, [false]),
         :ok <- validate_action_argument_option(action, :confirm, :type, [Type.String]),
         :ok <- validate_action_has_change(action, GenerateTokenChange),
         :ok <- validate_action_option(action, :require_atomic?, [false]) do
      accept_fields = MapSet.new(action.accept)

      strategy.monitor_fields
      |> MapSet.new()
      |> MapSet.difference(accept_fields)
      |> Enum.to_list()
      |> case do
        [] ->
          :ok

        _fields ->
          {:error,
           DslError.exception(
             path: [:actions, action.name, :accept],
             message: "The confirmation action must accept the monitored fields."
           )}
      end
    end
  end

  defp build_confirmed_at_attribute(_dsl_state, strategy) do
    Transformer.build_entity(Resource.Dsl, [:attributes], :attribute,
      name: strategy.confirmed_at_field,
      type: Type.UtcDatetimeUsec,
      allow_nil?: true,
      writable?: true
    )
  end

  defp validate_confirmed_at_attribute(dsl_state, strategy) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, strategy.confirmed_at_field),
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

  defp maybe_build_change(dsl_state, change_module) do
    with changes <- Resource.Info.changes(dsl_state),
         false <- Enum.any?(changes, &(&1.change == change_module)),
         {:ok, change} <-
           Transformer.build_entity(Resource.Dsl, [:changes], :change,
             change: change_module,
             on: [:create, :update]
           ) do
      {:ok, Transformer.add_entity(dsl_state, [:changes], change)}
    else
      true -> {:ok, dsl_state}
      {:error, reason} -> {:error, reason}
    end
  end
end
