defmodule AshAuthentication.Strategy.OAuth2.Transformer do
  @moduledoc """
  DSL transformer for oauth2 strategies.

  Iterates through any oauth2 strategies and ensures that all the correct
  actions and settings are in place.
  """

  use Spark.Dsl.Transformer
  alias Ash.{Resource, Type}
  alias AshAuthentication.{GenerateTokenChange, Info, Strategy.OAuth2}
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action

  @doc false
  @impl true
  @spec after?(module) :: boolean
  def after?(AshAuthentication.Transformer), do: true
  def after?(_), do: false

  @doc false
  @impl true
  @spec before?(module) :: boolean
  def before?(Resource.Transformers.DefaultAccept), do: true
  def before?(_), do: false

  @doc false
  @impl true
  @spec transform(map) ::
          :ok
          | {:ok, map()}
          | {:error, term()}
          | {:warn, map(), String.t() | [String.t()]}
          | :halt
  def transform(dsl_state) do
    dsl_state
    |> Info.authentication_strategies()
    |> Stream.filter(&is_struct(&1, OAuth2))
    |> Enum.reduce_while({:ok, dsl_state}, fn strategy, {:ok, dsl_state} ->
      case transform_strategy(strategy, dsl_state) do
        {:ok, dsl_state} -> {:cont, {:ok, dsl_state}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp transform_strategy(strategy, dsl_state) do
    with strategy <- set_defaults(strategy),
         {:ok, dsl_state} <- maybe_build_identity_relationship(dsl_state, strategy),
         :ok <- maybe_validate_register_action(dsl_state, strategy),
         :ok <- maybe_validate_sign_in_action(dsl_state, strategy),
         {:ok, resource} <- persisted_option(dsl_state, :module) do
      strategy = %{strategy | resource: resource}

      dsl_state =
        dsl_state
        |> Transformer.replace_entity(
          ~w[authentication strategies]a,
          strategy,
          &(&1.name == strategy.name)
        )
        |> then(fn dsl_state ->
          ~w[register_action_name sign_in_action_name]a
          |> Stream.map(&Map.get(strategy, &1))
          |> Enum.reduce(
            dsl_state,
            &Transformer.persist(&2, {:authentication_action, &1}, strategy)
          )
        end)

      {:ok, dsl_state}
    else
      {:error, reason} when is_binary(reason) ->
        {:error,
         DslError.exception(path: [:authentication, :strategies, strategy.name], message: reason)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp set_defaults(strategy) do
    strategy
    |> maybe_set_field_lazy(:register_action_name, &:"register_with_#{&1.name}")
    |> maybe_set_field_lazy(:sign_in_action_name, &:"sign_in_with_#{&1.name}")
  end

  defp maybe_build_identity_relationship(dsl_state, strategy)
       when is_falsy(strategy.identity_resource),
       do: {:ok, dsl_state}

  defp maybe_build_identity_relationship(dsl_state, strategy) do
    maybe_build_relationship(
      dsl_state,
      strategy.identity_relationship_name,
      &build_identity_relationship(&1, strategy)
    )
  end

  defp build_identity_relationship(_dsl_state, strategy) do
    Transformer.build_entity(Resource.Dsl, [:relationships], :has_many,
      name: strategy.identity_relationship_name,
      destination: strategy.identity_resource,
      destination_attribute: strategy.identity_relationship_user_id_attribute
    )
  end

  defp maybe_validate_register_action(dsl_state, strategy) when strategy.registration_enabled? do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.register_action_name),
         :ok <- validate_action_has_argument(action, :user_info),
         :ok <- validate_action_argument_option(action, :user_info, :type, [Type.Map, :map]),
         :ok <- validate_action_argument_option(action, :user_info, :allow_nil?, [false]),
         :ok <- validate_action_has_argument(action, :oauth_tokens),
         :ok <-
           validate_action_argument_option(action, :oauth_tokens, :type, [Type.Map, :map]),
         :ok <- validate_action_argument_option(action, :oauth_tokens, :allow_nil?, [false]),
         :ok <- maybe_validate_action_has_token_change(dsl_state, action),
         :ok <- validate_field_in_values(action, :upsert?, [true]),
         :ok <-
           validate_field_with(
             action,
             :upsert_identity,
             &(is_atom(&1) and not is_falsy(&1)),
             "Expected `upsert_identity` to be set"
           ),
         :ok <- maybe_validate_action_has_identity_change(action, strategy) do
      :ok
    else
      :error ->
        {:error, "Unable to validate register action"}

      {:error, reason} when is_binary(reason) ->
        {:error, "`#{inspect(strategy.register_action_name)}` action: #{reason}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_validate_register_action(_dsl_state, _strategy), do: :ok

  defp maybe_validate_action_has_token_change(dsl_state, action) do
    if Info.authentication_tokens_enabled?(dsl_state) do
      validate_action_has_change(action, GenerateTokenChange)
    else
      :ok
    end
  end

  defp maybe_validate_action_has_identity_change(_action, strategy)
       when is_falsy(strategy.identity_resource),
       do: :ok

  defp maybe_validate_action_has_identity_change(action, _strategy),
    do: validate_action_has_change(action, OAuth2.IdentityChange)

  defp maybe_validate_sign_in_action(_dsl_state, strategy) when strategy.registration_enabled?,
    do: :ok

  defp maybe_validate_sign_in_action(dsl_state, strategy) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.sign_in_action_name),
         :ok <- validate_action_has_argument(action, :user_info),
         :ok <- validate_action_argument_option(action, :user_info, :type, [Ash.Type.Map, :map]),
         :ok <- validate_action_argument_option(action, :user_info, :allow_nil?, [false]),
         :ok <- validate_action_has_argument(action, :oauth_tokens),
         :ok <-
           validate_action_argument_option(action, :oauth_tokens, :type, [Ash.Type.Map, :map]),
         :ok <- validate_action_argument_option(action, :oauth_tokens, :allow_nil?, [false]),
         :ok <- validate_action_has_preparation(action, OAuth2.SignInPreparation) do
      :ok
    else
      :error -> {:error, "Unable to validate sign in action"}
      {:error, reason} -> {:error, reason}
    end
  end
end
