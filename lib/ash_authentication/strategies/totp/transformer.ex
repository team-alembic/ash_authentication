# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.Transformer do
  @moduledoc """
  DSL transformer for the totp strategy.
  """
  alias AshAuthentication.Strategy
  alias AshAuthentication.Strategy.Totp
  alias Spark.Dsl.Transformer

  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Attribute

  @doc false
  @spec transform(Totp.t(), map) :: {:ok, Totp.t() | map} | {:error, Exception.t()}
  def transform(strategy, dsl) do
    with strategy <- maybe_set_field_lazy(strategy, :issuer, &to_string(&1.name)),
         :ok <- validate_identity_field(strategy.identity_field, dsl),
         :ok <- validate_secret_field(strategy.secret_field, dsl),
         :ok <- validate_last_totp_at_field(strategy.last_totp_at_field, dsl),
         strategy <-
           maybe_set_field_lazy(strategy, :setup_action_name, &:"setup_with_#{&1.name}"),
         {:ok, dsl} <-
           maybe_build_action(dsl, strategy.setup_action_name, &build_setup_action(&1, strategy)),
         :ok <- validate_setup_action(dsl, strategy),
         strategy <-
           maybe_set_field_lazy(strategy, :verify_action_name, &:"verify_with_#{&1.name}"),
         {:ok, dsl} <-
           maybe_build_action(
             dsl,
             strategy.verify_action_name,
             &build_verify_action(&1, strategy)
           ),
         {:ok, resource} <- persisted_option(dsl, :module) do
      strategy = %{strategy | resource: resource}

      {:ok,
       Transformer.replace_entity(
         [:authentication, :strategies],
         strategy,
         &(Strategy.name(&1) == strategy.name)
       )}
    end
  end

  defp validate_identity_field(identity_field, dsl) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, identity_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :public?, [true]) do
      validate_attribute_unique_constraint(dsl, [identity_field], resource)
    end
  end

  defp validate_secret_field(secret_field, dsl) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, secret_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :sensitive?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [false])
    end
  end

  defp build_setup_action(dsl, strategy) do
  end
end
