# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

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
      |> Enum.any?(fn {module, opts} ->
        cond do
          module == change_module ->
            true

          module == AshEvents.Events.ReplayChangeWrapper ->
            wrapped_change = opts[:change].change |> elem(0)
            wrapped_change == change_module

          true ->
            false
        end
      end)

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
  Validate that an action carries its strategy's brute-force preparation.

  A strategy adds the preparation to the actions it builds. An action defined
  on the resource instead, by hand or by a generator, has only what was written
  for it, so without this check a configured `brute_force_strategy` would
  protect nothing.

  `audit_log_preparations` is the preparation the strategy uses for
  `brute_force_strategy {:audit_log, name}`, or a list of preparations any one
  of which protects the action. The first is the one the error suggests.
  """
  @spec validate_brute_force_preparation(Actions.action(), map, module | [module, ...]) ::
          :ok | {:error, Exception.t()}
  def validate_brute_force_preparation(action, strategy, audit_log_preparations) do
    case Map.get(strategy, :brute_force_strategy) do
      {:audit_log, _audit_log_name} ->
        [suggested | _] = preparations = List.wrap(audit_log_preparations)

        require_brute_force_preparation(
          action,
          strategy,
          preparations,
          "{#{inspect(suggested)}, action_name: #{inspect(action.name)}}"
        )

      {:preparation, preparation} ->
        require_brute_force_preparation(action, strategy, [preparation], inspect(preparation))

      _ ->
        :ok
    end
  end

  defp require_brute_force_preparation(action, strategy, preparations, prepare_line) do
    if Enum.any?(preparations, &(validate_action_has_preparation(action, &1) == :ok)) do
      :ok
    else
      [suggested | _] = preparations

      {:error,
       DslError.exception(
         path: [:actions, action.name],
         message: """
         The `brute_force_strategy` of the #{inspect(strategy.name)} strategy applies to the
         action `#{inspect(action.name)}`, but that action is defined without the
         `#{inspect(suggested)}` preparation, so attempts on it would not be limited.

         Add this to the action:

             prepare #{prepare_line}

         or remove the action definition to use the one the strategy generates.
         """
       )}
    end
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
