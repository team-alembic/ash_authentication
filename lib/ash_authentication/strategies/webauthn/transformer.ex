defmodule AshAuthentication.Strategy.WebAuthn.Transformer do
  @moduledoc """
  DSL transformer for the WebAuthn strategy.

  Ensures all correct actions and settings are in place for both
  the user resource and the credential resource.
  """

  alias Ash.Resource
  alias AshAuthentication.{GenerateTokenChange, Strategy, Strategy.WebAuthn}
  alias Spark.Dsl.Transformer
  import AshAuthentication.Strategy.Custom.Helpers
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Attribute

  @doc false
  @spec transform(WebAuthn.t(), map) :: {:ok, WebAuthn.t() | map} | {:error, Exception.t()}
  def transform(strategy, dsl_state) do
    with :ok <- validate_identity_field(strategy.identity_field, dsl_state),
         strategy <-
           maybe_set_field_lazy(strategy, :register_action_name, &:"register_with_#{&1.name}"),
         strategy <-
           maybe_set_field_lazy(strategy, :sign_in_action_name, &:"sign_in_with_#{&1.name}"),
         strategy <-
           maybe_set_field_lazy(
             strategy,
             :store_credential_action_name,
             fn s -> :"store_#{s.name}_credential" end
           ),
         strategy <-
           maybe_set_field_lazy(
             strategy,
             :update_sign_count_action_name,
             fn s -> :"update_#{s.name}_sign_count" end
           ),
         strategy <-
           maybe_set_field_lazy(
             strategy,
             :list_credentials_action_name,
             fn s -> :"list_#{s.name}_credentials" end
           ),
         strategy <-
           maybe_set_field_lazy(
             strategy,
             :delete_credential_action_name,
             fn s -> :"delete_#{s.name}_credential" end
           ),
         strategy <-
           maybe_set_field_lazy(
             strategy,
             :update_credential_label_action_name,
             fn s -> :"update_#{s.name}_credential_label" end
           ),
         strategy <-
           maybe_set_field_lazy(
             strategy,
             :add_credential_action_name,
             fn s -> :"add_#{s.name}_credential" end
           ),
         {:ok, dsl_state} <-
           (if strategy.registration_enabled? do
              maybe_build_action(
                dsl_state,
                strategy.register_action_name,
                &build_register_action(&1, strategy)
              )
            else
              {:ok, dsl_state}
            end),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             strategy.sign_in_action_name,
             &build_sign_in_action(&1, strategy)
           ),
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
          actions = [strategy.sign_in_action_name]

          actions =
            if strategy.registration_enabled?,
              do: [strategy.register_action_name | actions],
              else: actions

          actions
          |> Enum.reject(&is_nil/1)
          |> register_strategy_actions(dsl_state, strategy)
        end)

      {:ok, dsl_state}
    end
  end

  defp validate_identity_field(identity_field, dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, identity_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :public?, [true]) do
      validate_attribute_unique_constraint(dsl_state, [identity_field], resource)
    end
  end

  defp build_register_action(dsl_state, strategy) do
    # identity_field is set via `accept`, not as an argument (matches Password pattern)
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: :credential_id,
        type: :binary,
        allow_nil?: false,
        description: "The WebAuthn credential ID from the authenticator."
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: :public_key,
        type: :map,
        allow_nil?: false,
        description: "The COSE public key from the authenticator."
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: :sign_count,
        type: :integer,
        allow_nil?: false,
        description: "The initial sign count from the authenticator."
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: :label,
        type: :string,
        default: "Security Key",
        description: "A human-readable label for the credential."
      )
    ]

    changes = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
        change: GenerateTokenChange,
        description: "Generate a JWT token for the newly registered user."
      )
    ]

    metadata =
      if AshAuthentication.Info.authentication_tokens_enabled?(dsl_state) do
        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :create], :metadata,
            name: :token,
            type: :string,
            allow_nil?: false,
            description: "A JWT which the user can use to authenticate."
          )
        ]
      else
        []
      end

    Transformer.build_entity(Resource.Dsl, [:actions], :create,
      name: strategy.register_action_name,
      accept: [strategy.identity_field],
      arguments: arguments,
      changes: changes,
      metadata: metadata,
      description: "Register a new user with a WebAuthn credential."
    )
  end

  defp build_sign_in_action(dsl_state, strategy) do
    identity_attribute = Resource.Info.attribute(dsl_state, strategy.identity_field)

    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: strategy.identity_field,
        type: identity_attribute.type,
        allow_nil?: false,
        description: "The identity to use for retrieving the user."
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: WebAuthn.SignInPreparation
      )
    ]

    metadata =
      if AshAuthentication.Info.authentication_tokens_enabled?(dsl_state) do
        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :read], :metadata,
            name: :token,
            type: :string,
            allow_nil?: false,
            description: "A JWT which the user can use to authenticate."
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
      description: "Sign in a user with a WebAuthn credential."
    )
  end
end
