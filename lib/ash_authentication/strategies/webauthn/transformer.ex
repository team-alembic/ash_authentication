# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Transformer do
  @moduledoc """
  DSL transformer for the WebAuthn strategy.

  Ensures all correct actions and settings are in place for both
  the user resource and the credential resource.
  """

  alias Ash.Resource
  alias AshAuthentication.{GenerateTokenChange, Strategy, Strategy.WebAuthn}
  alias Spark.Dsl.Transformer
  alias Spark.Error.DslError
  import AshAuthentication.Strategy.Custom.Helpers
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Attribute

  @doc false
  @spec transform(WebAuthn.t(), map) :: {:ok, WebAuthn.t() | map} | {:error, Exception.t()}
  # sobelow_skip ["DOS.BinToAtom"]
  def transform(strategy, dsl_state) do
    with :ok <- validate_identity(strategy, dsl_state),
         {:ok, dsl_state} <-
           maybe_build_relationship(
             dsl_state,
             strategy.credentials_relationship_name,
             &build_credentials_relationship(&1, strategy)
           ),
         :ok <- validate_credentials_relationship(strategy, dsl_state),
         strategy <-
           maybe_set_field_lazy(strategy, :register_action_name, &:"register_with_#{&1.name}"),
         strategy <-
           maybe_set_field_lazy(strategy, :sign_in_action_name, &:"sign_in_with_#{&1.name}"),
         strategy <-
           maybe_set_field_lazy(
             strategy,
             :sign_in_with_token_action_name,
             &:"sign_in_with_#{&1.name}_token"
           ),
         strategy <-
           maybe_set_field_lazy(strategy, :verify_action_name, &:"verify_#{&1.name}"),
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
           (if strategy.sign_in_enabled? do
              maybe_build_action(
                dsl_state,
                strategy.sign_in_action_name,
                &build_sign_in_action(&1, strategy)
              )
            else
              {:ok, dsl_state}
            end),
         {:ok, dsl_state} <-
           (if strategy.sign_in_enabled? do
              maybe_build_action(
                dsl_state,
                strategy.sign_in_with_token_action_name,
                &build_sign_in_with_token_action(&1, strategy)
              )
            else
              {:ok, dsl_state}
            end),
         {:ok, dsl_state} <-
           (if strategy.verify_enabled? do
              maybe_build_action(
                dsl_state,
                strategy.verify_action_name,
                &build_verify_action(&1, strategy)
              )
            else
              {:ok, dsl_state}
            end),
         {:ok, resource} <- persisted_option(dsl_state, :module) do
      strategy = %{strategy | resource: resource}

      dsl_state =
        Transformer.replace_entity(
          dsl_state,
          ~w[authentication strategies]a,
          strategy,
          &(Strategy.name(&1) == strategy.name)
        )

      dsl_state = register_webauthn_actions(dsl_state, strategy)

      {:ok, dsl_state}
    end
  end

  defp register_webauthn_actions(dsl_state, strategy) do
    actions = []

    actions =
      if strategy.sign_in_enabled?,
        do: [strategy.sign_in_action_name, strategy.sign_in_with_token_action_name | actions],
        else: actions

    actions =
      if strategy.registration_enabled?,
        do: [strategy.register_action_name | actions],
        else: actions

    actions =
      if strategy.verify_enabled?,
        do: [strategy.verify_action_name | actions],
        else: actions

    actions
    |> Enum.reject(&is_nil/1)
    |> register_strategy_actions(dsl_state, strategy)
  end

  # In passkey-first mode the user is resolved from the credential id alone,
  # so the user resource doesn't need an identity attribute at all.
  defp validate_identity(%{require_identity?: false}, _dsl_state), do: :ok

  defp validate_identity(strategy, dsl_state),
    do: validate_identity_field(strategy.identity_field, dsl_state)

  defp validate_identity_field(identity_field, dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, identity_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :public?, [true]) do
      validate_attribute_unique_constraint(dsl_state, [identity_field], resource)
    end
  end

  # The credential resource is declared `no_depend_modules`, so it may not be
  # compiled yet when this runs — we can't read the foreign key off its
  # `belongs_to`. Leave `destination_attribute` unset so Ash's own
  # `HasDestinationField` transformer derives it from *this* resource's name
  # (`Account` -> `:account_id`), which agrees with the credential resource
  # whenever its `belongs_to` is named after the user resource too — the
  # convention the installer generates and `BelongsTo` defaults to.
  #
  # Hardcoding `:user_id` here instead, as this used to, silently produced a
  # `has_many` pointing at a column that doesn't exist for any user resource
  # not called `User`. Where the derivation can't hold, the verifier compares
  # the two ends once the credential resource *is* compiled and tells you to
  # declare the relationship yourself (it will then be left untouched, per
  # `maybe_build_relationship/3`).
  defp build_credentials_relationship(_dsl_state, strategy) do
    Transformer.build_entity(Resource.Dsl, [:relationships], :has_many,
      name: strategy.credentials_relationship_name,
      destination: strategy.credential_resource
    )
  end

  defp validate_credentials_relationship(strategy, dsl_state) do
    case Resource.Info.relationship(dsl_state, strategy.credentials_relationship_name) do
      %{type: :has_many, destination: destination}
      when destination == strategy.credential_resource ->
        :ok

      %{type: type} ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message:
             "The `#{inspect(strategy.credentials_relationship_name)}` relationship must be a `has_many` to `#{inspect(strategy.credential_resource)}` (found `#{type}`)."
         )}
    end
  end

  defp build_register_action(dsl_state, strategy) do
    # identity_field is set via `accept`, not as an argument (matches Password pattern)
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: strategy.credentials_relationship_name,
        type: :map,
        allow_nil?: false,
        description: "The WebAuthn credential to create for the newly registered user."
      )
    ]

    changes = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
        change:
          {Ash.Resource.Change.ManageRelationship,
           argument: strategy.credentials_relationship_name,
           relationship: strategy.credentials_relationship_name,
           opts: [type: :direct_control]},
        description: "Create the WebAuthn credential as part of the same transaction as the user."
      ),
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
      accept: build_register_action_accept(strategy),
      arguments: arguments,
      changes: changes,
      metadata: metadata,
      description: "Register a new user with a WebAuthn credential."
    )
  end

  defp build_register_action_accept(%_{require_identity?: false} = strategy) do
    strategy.register_action_accept
    |> List.wrap()
    |> Strategy.CustomFields.accept_names()
    |> Enum.uniq()
  end

  defp build_register_action_accept(strategy) do
    [strategy.identity_field]
    |> Enum.concat(Strategy.CustomFields.accept_names(List.wrap(strategy.register_action_accept)))
    |> Enum.uniq()
  end

  defp build_sign_in_action(dsl_state, strategy) do
    arguments =
      if strategy.require_identity? do
        identity_attribute = Resource.Info.attribute(dsl_state, strategy.identity_field)
        identity_type = if identity_attribute, do: identity_attribute.type, else: Ash.Type.String

        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
            name: strategy.identity_field,
            type: identity_type,
            allow_nil?: false,
            description: "The identity to use for retrieving the user."
          )
        ]
      else
        # In passkey-first mode the identity attribute may not exist on the
        # resource; the user is resolved from the credential id in `Actions.sign_in/3`.
        []
      end

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

  defp build_verify_action(_dsl_state, strategy) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :raw_id,
        type: :string,
        allow_nil?: false,
        description: "The base64url-encoded credential id from the assertion."
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :authenticator_data,
        type: :string,
        allow_nil?: false,
        description: "The base64url-encoded authenticator data from the assertion."
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :signature,
        type: :string,
        allow_nil?: false,
        description: "The base64url-encoded signature from the assertion."
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :client_data_json,
        type: :string,
        allow_nil?: false,
        description: "The base64url-encoded client data JSON from the assertion."
      )
    ]

    metadata = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :metadata,
        name: :webauthn_verified_at,
        type: :utc_datetime_usec,
        allow_nil?: false,
        description: "The instant at which the second-factor verification succeeded."
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :metadata,
        name: :token,
        type: :string,
        allow_nil?: true,
        description:
          "A fresh JWT containing the `webauthn_verified_at` claim, when tokens are enabled."
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: strategy.verify_action_name,
      arguments: arguments,
      metadata: metadata,
      get?: true,
      description:
        "Verify a WebAuthn assertion as a second factor for the currently authenticated user."
    )
  end

  defp build_sign_in_with_token_action(_dsl_state, strategy) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :token,
        type: :string,
        allow_nil?: false,
        sensitive?: true,
        description: "The short-lived sign-in JWT issued by the WebAuthn ceremony."
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: WebAuthn.SignInWithTokenPreparation
      )
    ]

    metadata = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :metadata,
        name: :token,
        type: :string,
        allow_nil?: false,
        description: "A JWT which the user can use to authenticate to the API."
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: strategy.sign_in_with_token_action_name,
      arguments: arguments,
      preparations: preparations,
      metadata: metadata,
      get?: true,
      description:
        "Exchange a short-lived sign-in token issued by a WebAuthn ceremony for an authenticated session."
    )
  end
end
