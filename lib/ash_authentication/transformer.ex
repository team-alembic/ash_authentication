defmodule AshAuthentication.Transformer do
  @moduledoc """
  The Authentication transformer

  Sets up non-provider-specific configuration for authenticated resources.
  """

  use Spark.Dsl.Transformer
  alias Ash.Resource
  alias AshAuthentication.{Info, Strategy}
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
    with {:ok, dsl_state} <- maybe_set_domain(dsl_state, :authentication),
         :ok <- validate_at_least_one_strategy(dsl_state),
         :ok <- validate_unique_strategy_names(dsl_state),
         :ok <- validate_unique_add_on_names(dsl_state),
         {:ok, dsl_state} <- maybe_transform_token_lifetime(dsl_state),
         {:ok, get_by_subject_action_name} <-
           Info.authentication_get_by_subject_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             get_by_subject_action_name,
             &build_get_by_subject_action/1
           ),
         :ok <- validate_read_action(dsl_state, get_by_subject_action_name),
         subject_name <- find_or_generate_subject_name(dsl_state),
         current_user when is_atom(current_user) <- ensure_current_user_atom_exists(subject_name) do
      dsl_state =
        dsl_state
        |> Transformer.set_option([:authentication], :subject_name, subject_name)

      {:ok, dsl_state}
    end
  end

  defp maybe_transform_token_lifetime(dsl_state) do
    case Info.authentication_tokens_token_lifetime(dsl_state) do
      {:ok, {_ttl, unit}} when unit in ~w[days hours minutes seconds]a ->
        {:ok, dsl_state}

      {:ok, ttl} when is_integer(ttl) and ttl > 0 ->
        {:ok,
         Transformer.set_option(
           dsl_state,
           [:authentication, :tokens],
           :token_lifetime,
           {ttl, :hours}
         )}

      _ ->
        {:error,
         DslError.exception(
           path: [:authentication, :tokens],
           message: "Invalid token lifetime"
         )}
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

  # sobelow_skip ["DOS.StringToAtom"]
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

  # sobelow_skip ["DOS.StringToAtom"]
  defp ensure_current_user_atom_exists(subject_name),
    do: String.to_atom("current_#{subject_name}")

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

  defp validate_unique_add_on_names(dsl_state) do
    dsl_state
    |> Transformer.get_entities([:authentication, :add_ons])
    |> Enum.map(&Strategy.name/1)
    |> validate_unique("add on")
  end

  defp validate_unique_strategy_names(dsl_state) do
    dsl_state
    |> Transformer.get_entities([:authentication, :strategies])
    |> Enum.map(&Strategy.name/1)
    |> validate_unique("strategy")
  end

  defp validate_unique(strategy_names, descriptor) do
    duplicates =
      strategy_names
      |> Enum.frequencies()
      |> Enum.reject(&(elem(&1, 1) == 1))

    if Enum.any?(duplicates) do
      errors =
        duplicates
        |> Enum.map_join("\n", fn
          {name, 2} -> "  * #{descriptor} `#{inspect(name)}` is repeated twice."
          {name, n} -> "  * #{descriptor} `#{inspect(name)}` is repeated #{n} times."
        end)

      {:error,
       DslError.exception(
         path: [:authentication, :strategies],
         message: "Strategy names must be unique.\n\n#{errors}"
       )}
    else
      :ok
    end
  end
end
