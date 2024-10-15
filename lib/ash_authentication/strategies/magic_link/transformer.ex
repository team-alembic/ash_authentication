defmodule AshAuthentication.Strategy.MagicLink.Transformer do
  @moduledoc """
  DSL transformer for magic links.
  """

  alias Ash.Resource
  alias AshAuthentication.Strategy.MagicLink
  alias Spark.Dsl.Transformer
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Strategy.Custom.Helpers

  @doc false
  @spec transform(MagicLink.t(), dsl_state) :: {:ok, MagicLink.t() | dsl_state} | {:error, any}
        when dsl_state: map
  def transform(strategy, dsl_state) do
    with :ok <-
           validate_token_generation_enabled(
             dsl_state,
             "Token generation must be enabled for magic links to work."
           ),
         strategy <- maybe_set_sign_in_action_name(strategy),
         strategy <- maybe_set_request_action_name(strategy),
         strategy <- maybe_set_lookup_action_name(strategy),
         strategy <- maybe_transform_token_lifetime(strategy),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             strategy.sign_in_action_name,
             &build_sign_in_action(&1, strategy)
           ),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             strategy.request_action_name,
             &build_request_action(&1, strategy)
           ) do
      dsl_state =
        dsl_state
        |> then(
          &register_strategy_actions(
            [
              strategy.sign_in_action_name,
              strategy.request_action_name,
              strategy.lookup_action_name
            ],
            &1,
            strategy
          )
        )
        |> put_strategy(strategy)

      {:ok, dsl_state}
    end
  end

  defp maybe_transform_token_lifetime(strategy) when is_integer(strategy.token_lifetime),
    do: %{strategy | token_lifetime: {strategy.token_lifetime, :minutes}}

  defp maybe_transform_token_lifetime(strategy), do: strategy

  # sobelow_skip ["DOS.StringToAtom"]
  defp maybe_set_sign_in_action_name(strategy) when is_nil(strategy.sign_in_action_name),
    do: %{strategy | sign_in_action_name: String.to_atom("sign_in_with_#{strategy.name}")}

  defp maybe_set_sign_in_action_name(strategy), do: strategy

  # sobelow_skip ["DOS.StringToAtom"]
  defp maybe_set_request_action_name(strategy) when is_nil(strategy.request_action_name),
    do: %{strategy | request_action_name: String.to_atom("request_#{strategy.name}")}

  defp maybe_set_request_action_name(strategy), do: strategy

  # sobelow_skip ["DOS.StringToAtom"]
  defp maybe_set_lookup_action_name(strategy) when is_nil(strategy.lookup_action_name),
    do: %{strategy | lookup_action_name: String.to_atom("get_by_#{strategy.identity_field}")}

  defp maybe_set_lookup_action_name(strategy), do: strategy

  defp build_sign_in_action(dsl_state, strategy) do
    if strategy.registration_enabled? do
      arguments = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
          name: strategy.token_param_name,
          type: :string,
          allow_nil?: false
        )
      ]

      changes = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
          change: MagicLink.SignInChange
        )
      ]

      metadata = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :metadata,
          name: :token,
          type: :string,
          allow_nil?: false
        )
      ]

      identity =
        Enum.find(Ash.Resource.Info.identities(dsl_state), fn identity ->
          identity.keys == [strategy.identity_field]
        end)

      Transformer.build_entity(Resource.Dsl, [:actions], :create,
        name: strategy.sign_in_action_name,
        arguments: arguments,
        changes: changes,
        metadata: metadata,
        upsert?: true,
        upsert_identity: identity.name,
        upsert_fields: [strategy.identity_field]
      )
    else
      arguments = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
          name: strategy.token_param_name,
          type: :string,
          allow_nil?: false
        )
      ]

      preparations = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
          preparation: MagicLink.SignInPreparation
        )
      ]

      metadata = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :read], :metadata,
          name: :token,
          type: :string,
          allow_nil?: false
        )
      ]

      Transformer.build_entity(Resource.Dsl, [:actions], :read,
        name: strategy.sign_in_action_name,
        arguments: arguments,
        preparations: preparations,
        metadata: metadata,
        get?: true
      )
    end
  end

  defp build_request_action(dsl_state, strategy) do
    identity_attribute = Resource.Info.attribute(dsl_state, strategy.identity_field)

    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: strategy.identity_field,
        type: identity_attribute.type,
        allow_nil?: false
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: MagicLink.RequestPreparation
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: strategy.request_action_name,
      arguments: arguments,
      preparations: preparations
    )
  end
end
