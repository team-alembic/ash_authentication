# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RememberMe.Transformer do
  @moduledoc """
  DSL transformer for the remember me strategy.

  Iterates through any remember me authentication strategies and ensures that all
  the correct actions and settings are in place.
  """

  alias Ash.Resource
  alias AshAuthentication.{Strategy, Strategy.RememberMe}
  alias Spark.Dsl.Transformer
  import AshAuthentication.Strategy.Custom.Helpers
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action

  @doc false
  @spec transform(RememberMe.t(), map) :: {:ok, RememberMe.t() | map} | {:error, Exception.t()}
  # sobelow_skip ["DOS.BinToAtom"]
  def transform(strategy, dsl_state) do
    with strategy <-
           maybe_set_field_lazy(strategy, :sign_in_action_name, &:"sign_in_with_#{&1.name}"),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             strategy.sign_in_action_name,
             &build_sign_in_action(&1, strategy)
           ),
         :ok <- validate_sign_in_action(dsl_state, strategy),
         {:ok, resource} <- persisted_option(dsl_state, :module) do
      strategy = %{strategy | resource: resource}

      dsl_state =
        dsl_state
        |> Transformer.replace_entity(
          ~w[authentication strategies]a,
          strategy,
          &(Strategy.name(&1) == strategy.name)
        )
        |> then(fn dsl_state ->
          ~w[sign_in_action_name]a
          |> Enum.map(&Map.get(strategy, &1))
          |> register_strategy_actions(dsl_state, strategy)
        end)

      {:ok, dsl_state}
    end
  end

  defp build_sign_in_action(dsl_state, strategy) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :token,
        type: :string,
        allow_nil?: false,
        sensitive?: true,
        description: "The remember me token for authenticating"
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: RememberMe.SignInPreparation
      )
    ]

    metadata =
      if AshAuthentication.Info.authentication_tokens_enabled?(dsl_state) do
        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :read], :metadata,
            name: :token,
            type: :string,
            allow_nil?: false,
            description: "A JWT that can be used to authenticate the user"
          )
        ]
      else
        []
      end

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: strategy.sign_in_action_name,
      arguments: arguments,
      preparations: preparations,
      metadata: metadata,
      get?: true,
      description: "Attempt to sign in using a remember me token."
    )
  end

  defp validate_sign_in_action(dsl_state, strategy) do
    with {:ok, action} <-
           validate_action_exists(dsl_state, strategy.sign_in_action_name),
         :ok <-
           validate_action_argument_option(action, :token, :type, [Ash.Type.String, :string]),
         :ok <- validate_action_argument_option(action, :token, :allow_nil?, [false]),
         :ok <- validate_action_argument_option(action, :token, :sensitive?, [true]) do
      validate_action_has_preparation(action, RememberMe.SignInPreparation)
    end
  end
end
