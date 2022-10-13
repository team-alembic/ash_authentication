defmodule AshAuthentication.Transformer do
  @moduledoc """
  The Authentication transformer

  Sets the authentication API and subject_name for the resource.
  """

  use Spark.Dsl.Transformer
  alias AshAuthentication.Info
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action

  @doc false
  @impl true
  @spec after?(any) :: boolean()
  def after?(Ash.Resource.Transformers.ValidatePrimaryActions), do: true
  def after?(_), do: false

  @doc false
  @impl true
  @spec before?(any) :: boolean
  def before?(Ash.Resource.Transformers.DefaultAccept), do: true
  def before?(_), do: false

  @doc false
  @impl true
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with {:ok, api} <- validate_api_presence(dsl_state),
         :ok <- validate_at_least_one_authentication_provider(dsl_state),
         :ok <- validate_read_action(dsl_state),
         subject_name <- find_or_generate_subject_name(dsl_state) do
      authentication =
        dsl_state
        |> Transformer.get_persisted(:authentication, %{providers: []})
        |> Map.put(:subject_name, subject_name)
        |> Map.put(:api, api)

      dsl_state =
        dsl_state
        |> Transformer.persist(:authentication, authentication)
        |> Transformer.set_option([:authentication], :subject_name, subject_name)

      {:ok, dsl_state}
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

  defp validate_api_presence(dsl_state) do
    case Transformer.get_option(dsl_state, [:authentication], :api) do
      nil ->
        {:error,
         DslError.exception(
           path: [:authentication, :api],
           message: "An API module must be present"
         )}

      api ->
        {:ok, api}
    end
  end

  defp validate_at_least_one_authentication_provider(dsl_state) do
    ok? =
      dsl_state
      |> Transformer.get_persisted(:extensions, [])
      |> Enum.any?(&Spark.implements_behaviour?(&1, AshAuthentication.Provider))

    if ok?,
      do: :ok,
      else:
        {:error,
         DslError.exception(
           path: [:extensions],
           message:
             "At least one authentication provider extension must also be present.  See the documentation for more information."
         )}
  end

  defp validate_read_action(dsl_state) do
    action_name = Info.read_action_name(dsl_state)

    if has_valid_read_action?(dsl_state, action_name) || has_primary_read_action?(dsl_state),
      do: :ok,
      else:
        {:error,
         DslError.exception(
           path: [:actions],
           message:
             "Expected resource to have either a configured read action, or a default, primary read action"
         )}
  end

  defp has_valid_read_action?(_dsl_state, :error), do: false

  defp has_valid_read_action?(dsl_state, {:ok, action_name}) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_field_in_values(action, :type, [:read]) do
      true
    else
      _ -> false
    end
  end

  defp has_primary_read_action?(dsl_state) do
    dsl_state
    |> Transformer.get_entities([:actions])
    |> Enum.any?(&(&1.type == :read && &1.primary?))
  end
end
