defmodule AshAuthentication.Transformer do
  @moduledoc """
  The Authentication transformer

  Sets up non-provider-specific configuration for authenticated resources.
  """

  use Spark.Dsl.Transformer
  alias Ash.Resource
  alias AshAuthentication.{Info, TokenResource}
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action

  @doc false
  @impl true
  @spec after?(any) :: boolean()
  def after?(Resource.Transformers.ValidatePrimaryActions), do: true
  def after?(_), do: false

  @doc false
  @impl true
  @spec before?(any) :: boolean
  def before?(Resource.Transformers.DefaultAccept), do: true
  def before?(_), do: false

  @doc false
  @impl true
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with {:ok, _api} <- validate_api_presence(dsl_state),
         :ok <- validate_at_least_one_strategy(dsl_state),
         {:ok, get_by_subject_action_name} <-
           Info.authentication_get_by_subject_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             get_by_subject_action_name,
             &build_get_by_subject_action/1
           ),
         :ok <- validate_read_action(dsl_state, get_by_subject_action_name),
         :ok <- validate_token_resource(dsl_state),
         subject_name <- find_or_generate_subject_name(dsl_state) do
      dsl_state =
        dsl_state
        |> Transformer.set_option([:authentication], :subject_name, subject_name)

      {:ok, dsl_state}
    end
  end

  defp build_get_by_subject_action(dsl_state) do
    with {:ok, get_by_subject_action_name} <-
           Info.authentication_get_by_subject_action_name(dsl_state) do
      Transformer.build_entity(Resource.Dsl, [:actions], :read,
        name: get_by_subject_action_name,
        get?: true
      )
    end
  end

  defp find_or_generate_subject_name(dsl_state) do
    with nil <- Transformer.get_option(dsl_state, [:authentication], :subject_name),
         nil <- Transformer.get_option(dsl_state, [:resource], :short_name) do
      # We have to do this because the resource has not yet been compiled, so we can't call `default_short_name/0`.
      dsl_state
      |> Transformer.get_persisted(:module)
      |> Module.split()
      |> List.last()
      |> Macro.underscore()
      |> String.to_atom()
    end
  end

  defp validate_token_resource(dsl_state) do
    if_tokens_enabled(dsl_state, fn dsl_state ->
      with {:ok, resource} when is_truthy(resource) <-
             Info.authentication_tokens_token_resource(dsl_state),
           :ok <- assert_resource_has_extension(resource, TokenResource) do
        :ok
      else
        {:ok, falsy} when is_falsy(falsy) -> :ok
        {:error, reason} -> {:error, reason}
      end
    end)
  end

  defp if_tokens_enabled(dsl_state, validator) when is_function(validator, 1) do
    if Info.authentication_tokens_enabled?(dsl_state) do
      validator.(dsl_state)
    else
      :ok
    end
  end

  defp validate_api_presence(dsl_state) do
    with api when not is_nil(api) <- Transformer.get_option(dsl_state, [:authentication], :api),
         true <- function_exported?(api, :spark_is, 0),
         Ash.Api <- api.spark_is() do
      {:ok, api}
    else
      nil ->
        {:error,
         DslError.exception(
           path: [:authentication, :api],
           message: "An API module must be present"
         )}

      _ ->
        {:error,
         DslError.exception(
           path: [:authentication, :api],
           message: "Module is not an Ash.Api."
         )}
    end
  end

  defp validate_at_least_one_strategy(dsl_state) do
    ok? =
      dsl_state
      |> Transformer.get_entities([:authentication, :strategies])
      |> Enum.any?()

    if ok?,
      do: :ok,
      else:
        {:error,
         DslError.exception(
           path: [:authentication, :strategies],
           message: "Expected at least one authentication strategy"
         )}
  end

  defp validate_read_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_field_in_values(action, :type, [:read]) do
      :ok
    else
      _ ->
        {:error,
         DslError.exception(
           path: [:actions],
           message: "Expected resource to have either read action named `#{action_name}`"
         )}
    end
  end
end
