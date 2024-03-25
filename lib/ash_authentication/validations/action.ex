defmodule AshAuthentication.Validations.Action do
  @moduledoc """
  Validation helpers for Resource actions.
  """
  import AshAuthentication.Utils
  alias Ash.Resource.{Actions, Info}
  alias Spark.Error.DslError

  @doc """
  Validate that a named action actually exists.
  """
  @spec validate_action_exists(map, atom) ::
          {:ok, Actions.action()} | {:error, Exception.t() | String.t()}
  def validate_action_exists(dsl_state, action_name) do
    case Info.action(dsl_state, action_name) do
      action when is_map(action) ->
        {:ok, action}

      _ ->
        {:error,
         DslError.exception(
           path: [:actions],
           message: "Expected an action named `#{inspect(action_name)}` to be present"
         )}
    end
  end

  @doc """
  Validate an action's argument has an option set to one of the provided values.
  """
  @spec validate_action_argument_option(Actions.action(), atom, atom, [any]) ::
          :ok | {:error, Exception.t() | String.t()}
  def validate_action_argument_option(action, argument_name, field, values) do
    with argument when is_map(argument) <-
           Enum.find(action.arguments, :missing_argument, &(&1.name == argument_name)),
         {:ok, value} <- Map.fetch(argument, field),
         true <- value in values do
      :ok
    else
      :missing_argument ->
        {:error,
         DslError.exception(
           path: [:actions, :argument],
           message:
             "The action `#{inspect(action.name)}` should have an argument named `#{inspect(argument_name)}`"
         )}

      :error ->
        {:error,
         DslError.exception(
           path: [:actions, :argument],
           message:
             "The argument `#{inspect(argument_name)}` on action `#{inspect(action.name)}` is missing the `#{inspect(field)}` property"
         )}

      false ->
        case values do
          [] ->
            {:error,
             DslError.exception(
               path: [:actions, :argument],
               message:
                 "The argument `#{inspect(argument_name)}` on action `#{inspect(action.name)}` should not have `#{inspect(field)}` set"
             )}

          [expected] ->
            {:error,
             DslError.exception(
               path: [:actions, :argument],
               message:
                 "The argument `#{inspect(argument_name)}` on action `#{inspect(action.name)}` should have `#{inspect(field)}` set to `#{inspect(expected)}`"
             )}

          expected ->
            expected =
              expected
              |> Enum.map(&"`#{inspect(&1)}`")
              |> to_sentence(final: "or")

            {:error,
             DslError.exception(
               path: [:actions, :argument],
               message:
                 "The argument `#{inspect(argument_name)}` on action `#{inspect(action.name)}` should have `#{inspect(field)}` set to one of #{expected}"
             )}
        end
    end
  end

  @doc """
  Validate the presence of an argument on an action.
  """
  @spec validate_action_has_argument(Actions.action(), atom) :: :ok | {:error, Exception.t()}
  def validate_action_has_argument(action, argument_name) do
    if Enum.any?(action.arguments, &(&1.name == argument_name)),
      do: :ok,
      else:
        {:error,
         DslError.exception(
           path: [:actions, :argument],
           message:
             "Expected the action `#{inspect(action.name)}` to have an argument named `#{inspect(argument_name)}`."
         )}
  end

  @doc """
  Validate the presence of the named change module on an action.
  """
  @spec validate_action_has_change(Actions.action(), module) ::
          :ok | {:error, Exception.t()}
  def validate_action_has_change(action, change_module) do
    has_change? =
      action
      |> Map.get(:changes, [])
      |> Enum.map(&Map.get(&1, :change))
      |> Enum.reject(&is_nil/1)
      |> Enum.any?(&(elem(&1, 0) == change_module))

    if has_change?,
      do: :ok,
      else:
        {:error,
         DslError.exception(
           path: [:actions, :change],
           message:
             "The action `#{inspect(action.name)}` should have the `#{inspect(change_module)}` change present."
         )}
  end

  @doc """
  Validate the presence of the named manual module on an action.
  """
  @spec validate_action_has_manual(Actions.action(), module) ::
          :ok | {:error, Exception.t()}
  def validate_action_has_manual(action, manual_module) do
    has_manual? =
      action
      |> Map.get(:manual)
      |> then(fn {module, _args} ->
        module == manual_module
      end)

    if has_manual?,
      do: :ok,
      else:
        {:error,
         DslError.exception(
           path: [:actions, :manual],
           message:
             "The action `#{inspect(action.name)}` should have the `#{inspect(manual_module)}` manual present."
         )}
  end

  @doc """
  Validate the presence of the named validation module on an action.
  """
  @spec validate_action_has_validation(Actions.action(), module) ::
          :ok | {:error, Exception.t()}
  def validate_action_has_validation(action, validation_module) do
    has_validation? =
      action
      |> Map.get(:changes, [])
      |> Enum.map(&Map.get(&1, :validation))
      |> Enum.reject(&is_nil/1)
      |> Enum.any?(&(elem(&1, 0) == validation_module))

    if has_validation?,
      do: :ok,
      else:
        {:error,
         DslError.exception(
           path: [:actions, :validation],
           message:
             "The action `#{inspect(action.name)}` should have the `#{inspect(validation_module)}` validation present."
         )}
  end

  @doc """
  Validate the presence of the named preparation module on an action.
  """
  @spec validate_action_has_preparation(Actions.action(), module) ::
          :ok | {:error, Exception.t()}
  def validate_action_has_preparation(action, preparation_module) do
    has_preparation? =
      action
      |> Map.get(:preparations, [])
      |> Enum.map(&Map.get(&1, :preparation))
      |> Enum.reject(&is_nil/1)
      |> Enum.any?(&(elem(&1, 0) == preparation_module))

    if has_preparation?,
      do: :ok,
      else:
        {:error,
         DslError.exception(
           path: [:actions, :preparation],
           message:
             "The action `#{inspect(action.name)}` should have the `#{inspect(preparation_module)}` preparation present."
         )}
  end

  @doc """
  Validate the action has the provided option.
  """
  @spec validate_action_option(Actions.action(), atom, [any]) :: :ok | {:error, Exception.t()}
  def validate_action_option(action, field, values) do
    with {:ok, value} <- Map.fetch(action, field),
         true <- value in values do
      :ok
    else
      :error ->
        {:error,
         DslError.exception(
           path: [:actions, action.name, field],
           message:
             "The action `#{inspect(action.name)}` is missing the `#{inspect(field)}` option set"
         )}

      false ->
        case values do
          [] ->
            {:error,
             DslError.exception(
               path: [:actions, action.name, field],
               message:
                 "The action `#{inspect(action.name)}` should not have the `#{inspect(field)}` option set"
             )}

          [expected] ->
            {:error,
             DslError.exception(
               path: [:actions, action.name, field],
               message:
                 "The action `#{inspect(action.name)}` should have the `#{inspect(field)}` option set to `#{inspect(expected)}`"
             )}

          expected ->
            expected = expected |> Enum.map(&"`#{inspect(&1)}`") |> to_sentence(final: "or")

            {:error,
             DslError.exception(
               path: [:actions, action.name, field],
               message:
                 "The action `#{inspect(action.name)}` should have the `#{inspect(field)}` option set to one of #{expected}"
             )}
        end
    end
  end
end
