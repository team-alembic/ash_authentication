defmodule AshAuthentication.Validations.ActionValidators do
  @moduledoc """
  Behaviour for action validation implementations.

  This behaviour defines the callback interface for validating Ash Resource actions
  in the context of AshAuthentication. Implementations of this behaviour can be
  used to customize validation logic while maintaining the same interface.
  """

  alias Ash.Resource.Actions

  @doc """
  Validate that a named action actually exists.
  """
  @callback validate_action_exists(map, atom) ::
              {:ok, Actions.action()} | {:error, Exception.t() | String.t()}

  @doc """
  Validate an action's argument has an option set to one of the provided values.
  """
  @callback validate_action_argument_option(Actions.action(), atom, atom, [any]) ::
              :ok | {:error, Exception.t() | String.t()}

  @doc """
  Validate the presence of an argument on an action.
  """
  @callback validate_action_has_argument(Actions.action(), atom) :: :ok | {:error, Exception.t()}

  @doc """
  Validate the presence of the named change module on an action.
  """
  @callback validate_action_has_change(Actions.action(), module) ::
              :ok | {:error, Exception.t()}

  @doc """
  Validate the presence of the named manual module on an action.
  """
  @callback validate_action_has_manual(Actions.action(), module) ::
              :ok | {:error, Exception.t()}

  @doc """
  Validate the presence of the named validation module on an action.
  """
  @callback validate_action_has_validation(Actions.action(), module) ::
              :ok | {:error, Exception.t()}

  @doc """
  Validate the presence of the named preparation module on an action.
  """
  @callback validate_action_has_preparation(Actions.action(), module) ::
              :ok | {:error, Exception.t()}

  @doc """
  Validate the action has the provided option.
  """
  @callback validate_action_option(Actions.action(), atom, [any]) :: :ok | {:error, Exception.t()}
end
