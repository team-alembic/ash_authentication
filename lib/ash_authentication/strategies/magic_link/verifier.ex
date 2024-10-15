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
         :ok <- validate_request_action(dsl_state, strategy, identity_attribute),
         :ok <- prevent_hijacking(dsl_state, strategy) do
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
         :ok <- validate_field_in_values(action, :type, [:read, :action]) do
      case action.type do
        :read ->
          validate_action_has_preparation(action, MagicLink.RequestPreparation)

        _ ->
          with {:ok, action} <- validate_action_exists(dsl_state, strategy.lookup_action_name),
               :ok <- validate_action_has_argument(action, identity_attribute.name),
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
               :ok <- validate_action_option(action, :get?, [true]) do
            :ok
          else
            {:error, error} ->
              {:error, error}
          end
      end
    else
      {:error, message} when is_binary(message) ->
        {:error,
         DslError.exception(
           path: [:actions, strategy.request_action_name],
           message: message
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
         :ok <- validate_field_in_values(action, :type, [:read, :create]) do
      if action.type == :read do
        validate_action_has_preparation(action, MagicLink.SignInPreparation)
      else
        validate_action_has_change(action, MagicLink.SignInChange)
      end
    else
      {:error, message} when is_binary(message) ->
        {:error,
         DslError.exception(
           path: [:actions, :read, strategy.sign_in_action_name, :type],
           message: message
         )}

      {:error, exception} when is_exception(exception) ->
        {:error, exception}
    end
  end

  defp prevent_hijacking(_dsl_state, %{prevent_hijacking?: false}), do: :ok
  defp prevent_hijacking(_dsl_state, %{registration_enabled?: false}), do: :ok

  defp prevent_hijacking(dsl_state, strategy) do
    if could_be_hijacked?(dsl_state) && !has_confirmation_add_on?(dsl_state, strategy) do
      {:error,
       DslError.exception(
         path: [:authentication, :strategies, strategy.name],
         message: """
         If you have a magic strategy and a password strategy that support registration and share an identity field,
         you must also have a confirmation add-on that monitors that identity field.

         This is to prevent from account hijacking.

         For more information, see the confirmation tutorial on hexdocs.
         """
       )}
    else
      :ok
    end
  end

  defp could_be_hijacked?(dsl_state) do
    Enum.any?(AshAuthentication.Info.authentication_strategies(dsl_state), fn other_strategy ->
      other_strategy.__struct__ == AshAuthentication.Strategy.Password &&
        other_strategy.registration_enabled?
    end)
  end

  defp has_confirmation_add_on?(dsl_state, strategy) do
    Enum.any?(AshAuthentication.Info.authentication_add_ons(dsl_state), fn add_on ->
      add_on.__struct__ == AshAuthentication.AddOn.Confirmation &&
        strategy.identity_field in add_on.monitor_fields
    end)
  end
end
