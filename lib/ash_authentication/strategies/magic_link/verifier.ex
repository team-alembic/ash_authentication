defmodule AshAuthentication.Strategy.MagicLink.Verifier do
  @moduledoc """
  DSL verifier for magic links.
  """

  alias AshAuthentication.{Strategy.MagicLink}
  alias Spark.Error.DslError
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @spec verify(MagicLink.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with {:ok, identity_attribute} <- validate_identity_attribute(dsl_state, strategy),
         :ok <- validate_request_action(dsl_state, strategy, identity_attribute) do
      validate_sign_in_action(dsl_state, strategy)
    end
  end

  defp validate_identity_attribute(dsl_state, strategy) do
    with {:ok, identity_attribute} <- find_attribute(dsl_state, strategy.identity_field),
         :ok <-
           validate_attribute_unique_constraint(
             dsl_state,
             [strategy.identity_field],
             strategy.resource
           ) do
      {:ok, identity_attribute}
    end
  end

  defp validate_request_action(dsl_state, strategy, identity_attribute) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.request_action_name),
         :ok <- validate_action_has_argument(action, strategy.identity_field),
         :ok <-
           validate_action_argument_option(
             action,
             strategy.identity_field,
             :type,
             [identity_attribute.type]
           ),
         :ok <-
           validate_action_argument_option(action, strategy.identity_field, :allow_nil?, [
             false
           ]),
         :ok <- validate_action_has_preparation(action, MagicLink.RequestPreparation),
         :ok <- validate_field_in_values(action, :type, [:read]) do
      :ok
    else
      {:error, message} when is_binary(message) ->
        {:error,
         DslError.exception(
           path: [:actions, :read, strategy.request_action_name, :type],
           mesasge: message
         )}

      {:error, exception} when is_exception(exception) ->
        {:error, exception}
    end
  end

  defp validate_sign_in_action(dsl_state, strategy) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.sign_in_action_name),
         :ok <- validate_action_has_argument(action, strategy.token_param_name),
         :ok <-
           validate_action_argument_option(action, strategy.token_param_name, :type, [
             :string,
             Ash.Type.String
           ]),
         :ok <-
           validate_action_argument_option(action, strategy.token_param_name, :allow_nil?, [false]),
         :ok <- validate_action_has_preparation(action, MagicLink.SignInPreparation),
         :ok <- validate_field_in_values(action, :type, [:read]) do
      :ok
    else
      {:error, message} when is_binary(message) ->
        {:error,
         DslError.exception(
           path: [:actions, :read, strategy.sign_in_action_name, :type],
           mesasge: message
         )}

      {:error, exception} when is_exception(exception) ->
        {:error, exception}
    end
  end
end
