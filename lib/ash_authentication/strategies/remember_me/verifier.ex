defmodule AshAuthentication.Strategy.RememberMe.Verifier do
  @moduledoc """
  DSL verifier for magic links.
  """

  alias AshAuthentication.{Strategy.RememberMe}
  # alias Spark.Error.DslError
  import AshAuthentication.Validations
  # import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @spec verify(RememberMe.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with {:ok, _dent} <- validate_identity_attribute(dsl_state, strategy) do
      :ok
    end
    # with {:ok, identity_attribute} <- validate_identity_attribute(dsl_state, strategy),
    #      :ok <- validate_request_action(dsl_state, strategy, identity_attribute),
    #      :ok <- prevent_hijacking(dsl_state, strategy) do
    #   validate_sign_in_action(dsl_state, strategy)
    # end
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
end
