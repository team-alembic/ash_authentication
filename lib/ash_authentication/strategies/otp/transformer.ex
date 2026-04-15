# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.Transformer do
  @moduledoc """
  DSL transformer for OTP strategy.
  """

  alias Ash.Resource
  alias AshAuthentication.Strategy.Otp
  alias Spark.Dsl.Transformer
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Strategy.Custom.Helpers

  @doc false
  @spec transform(Otp.t(), dsl_state) :: {:ok, Otp.t() | dsl_state} | {:error, any}
        when dsl_state: map
  def transform(strategy, dsl_state) do
    with :ok <-
           validate_token_generation_enabled(
             dsl_state,
             "Token generation must be enabled for the OTP strategy to work."
           ),
         strategy <- maybe_set_sign_in_action_name(strategy),
         strategy <- maybe_set_request_action_name(strategy),
         strategy <- maybe_set_lookup_action_name(strategy),
         strategy <- maybe_set_otp_generator(strategy),
         strategy <- maybe_transform_otp_lifetime(strategy),
         strategy <- transform_audit_log_window(strategy),
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

  defp maybe_transform_otp_lifetime(strategy) when is_integer(strategy.otp_lifetime),
    do: %{strategy | otp_lifetime: {strategy.otp_lifetime, :minutes}}

  defp maybe_transform_otp_lifetime(strategy), do: strategy

  defp transform_audit_log_window(strategy) when is_integer(strategy.audit_log_window),
    do: %{strategy | audit_log_window: strategy.audit_log_window * 60}

  defp transform_audit_log_window(strategy) when is_tuple(strategy.audit_log_window) do
    {value, unit} = strategy.audit_log_window

    seconds =
      case unit do
        :days -> value * 24 * 60 * 60
        :hours -> value * 60 * 60
        :minutes -> value * 60
        :seconds -> value
      end

    %{strategy | audit_log_window: seconds}
  end

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

  defp maybe_set_otp_generator(strategy) when is_nil(strategy.otp_generator),
    do: %{strategy | otp_generator: Otp.DefaultGenerator}

  defp maybe_set_otp_generator(strategy), do: strategy

  defp build_sign_in_action(dsl_state, strategy) do
    if strategy.registration_enabled? do
      build_sign_in_create_action(dsl_state, strategy)
    else
      build_sign_in_read_action(dsl_state, strategy)
    end
  end

  defp build_sign_in_create_action(dsl_state, strategy) do
    identity_attribute = Resource.Info.attribute(dsl_state, strategy.identity_field)

    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: strategy.identity_field,
        type: identity_attribute.type,
        allow_nil?: false
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: strategy.otp_param_name,
        type: :string,
        allow_nil?: false
      )
    ]

    changes = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
        change: Otp.SignInChange
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
  end

  defp build_sign_in_read_action(dsl_state, strategy) do
    identity_attribute = Resource.Info.attribute(dsl_state, strategy.identity_field)

    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: strategy.identity_field,
        type: identity_attribute.type,
        allow_nil?: false
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: strategy.otp_param_name,
        type: :string,
        allow_nil?: false
      )
    ]

    preparations =
      brute_force_preparations(strategy, strategy.sign_in_action_name) ++
        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
            preparation: Otp.SignInPreparation
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

  defp build_request_action(dsl_state, strategy) do
    identity_attribute = Resource.Info.attribute(dsl_state, strategy.identity_field)

    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: strategy.identity_field,
        type: identity_attribute.type,
        allow_nil?: false
      )
    ]

    preparations =
      brute_force_preparations(strategy, strategy.request_action_name) ++
        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
            preparation: Otp.RequestPreparation
          )
        ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: strategy.request_action_name,
      arguments: arguments,
      preparations: preparations
    )
  end

  defp brute_force_preparations(strategy, action_name) do
    case strategy.brute_force_strategy do
      {:preparation, preparation} ->
        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
            preparation: preparation
          )
        ]

      {:audit_log, _audit_log_name} ->
        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
            preparation:
              {AshAuthentication.AddOn.AuditLog.BruteForcePreparation, action_name: action_name}
          )
        ]

      _ ->
        []
    end
  end
end
