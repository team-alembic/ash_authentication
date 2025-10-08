# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.ApiKey.Verifier do
  @moduledoc """
  DSL verifier for API key authentication.
  """

  alias Ash.Resource.Info, as: ResourceInfo
  alias AshAuthentication.{Strategy.ApiKey}
  alias Spark.Dsl.Transformer
  alias Spark.Error.DslError
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action

  @doc false
  @spec verify(ApiKey.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with :ok <- validate_api_key_relationship(dsl_state, strategy),
         :ok <- validate_multitenancy_relationship(dsl_state, strategy),
         :ok <- validate_api_key_hash_attribute(dsl_state, strategy),
         :ok <- validate_api_key_id_attribute(dsl_state, strategy) do
      validate_sign_in_action(dsl_state, strategy)
    end
  end

  defp validate_api_key_relationship(dsl_state, strategy) do
    case ResourceInfo.relationship(dsl_state, strategy.api_key_relationship) do
      nil ->
        resource = Transformer.get_persisted(dsl_state, :module)

        {:error,
         DslError.exception(
           path: [:relationships],
           message:
             "The resource `#{inspect(resource)}` does not define a relationship named `#{inspect(strategy.api_key_relationship)}`"
         )}

      _relationship ->
        :ok
    end
  end

  defp validate_multitenancy_relationship(_dsl_state, %{multitenancy_relationship: nil}), do: :ok

  defp validate_multitenancy_relationship(dsl_state, strategy) do
    relationship = ResourceInfo.relationship(dsl_state, strategy.api_key_relationship)
    destination = relationship.destination

    case ResourceInfo.relationship(destination, strategy.multitenancy_relationship) do
      nil ->
        {:error,
         DslError.exception(
           path: [:relationships],
           message:
             "The API key resource `#{inspect(destination)}` does not define a relationship named `#{inspect(strategy.multitenancy_relationship)}`"
         )}

      _relationship ->
        :ok
    end
  end

  defp validate_api_key_hash_attribute(dsl_state, strategy) do
    relationship = ResourceInfo.relationship(dsl_state, strategy.api_key_relationship)
    destination = relationship.destination

    case ResourceInfo.attribute(destination, strategy.api_key_hash_attribute) do
      nil ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message:
             "The API key resource `#{inspect(destination)}` does not define an attribute named `#{inspect(strategy.api_key_hash_attribute)}`"
         )}

      _attribute ->
        :ok
    end
  end

  defp validate_api_key_id_attribute(dsl_state, strategy) do
    relationship = ResourceInfo.relationship(dsl_state, strategy.api_key_relationship)
    destination = relationship.destination

    case ResourceInfo.attribute(destination, :id) do
      nil ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message:
             "The API key resource `#{inspect(destination)}` does not define an attribute named `id`"
         )}

      attribute ->
        validate_id_is_primary_key(dsl_state, destination, attribute)
    end
  end

  defp validate_id_is_primary_key(_dsl_state, destination, attribute) do
    if attribute.primary_key? do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:authentication, :strategies],
         message: "The API key resource `#{inspect(destination)}` must have `id` as a primary key"
       )}
    end
  end

  defp validate_sign_in_action(dsl_state, strategy) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.sign_in_action_name),
         :ok <- validate_action_has_argument(action, :api_key),
         :ok <-
           validate_action_argument_option(action, :api_key, :type, [
             :string,
             Ash.Type.String
           ]),
         :ok <-
           validate_action_argument_option(action, :api_key, :allow_nil?, [false]),
         :ok <- validate_field_in_values(action, :type, [:read]) do
      validate_action_has_preparation(action, ApiKey.SignInPreparation)
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
end
