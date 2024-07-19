defmodule AshAuthentication.Verifier do
  @moduledoc """
  The Authentication verifier.

  Checks configuration constraints after compile.
  """

  use Spark.Dsl.Verifier
  alias AshAuthentication.{Info, Strategy, Strategy.Password}
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Utils

  @doc false
  @impl true
  @spec verify(map) ::
          :ok
          | {:error, term}
          | {:warn, String.t() | list(String.t())}
  def verify(dsl_state) do
    with {:ok, _domain} <- validate_domain_presence(dsl_state),
         :ok <- validate_tokens_may_be_required(dsl_state) do
      validate_token_resource(dsl_state)
    end
  end

  defp validate_domain_presence(dsl_state) do
    with domain when not is_nil(domain) <-
           Transformer.get_option(dsl_state, [:authentication], :domain),
         :ok <- assert_is_module(domain),
         true <- function_exported?(domain, :spark_is, 0),
         Ash.Domain <- domain.spark_is() do
      {:ok, domain}
    else
      nil ->
        {:error,
         DslError.exception(
           path: [:authentication, :domain],
           message: "A domain module must be present"
         )}

      _ ->
        {:error,
         DslError.exception(
           path: [:authentication, :domain],
           message: "Module is not an `Ash.Domain`."
         )}
    end
  end

  defp validate_tokens_may_be_required(dsl_state) do
    strategies_requiring_tokens =
      dsl_state
      |> Info.authentication_strategies()
      |> Enum.filter(&Strategy.tokens_required?/1)

    tokens_enabled? =
      dsl_state
      |> Info.authentication_tokens_enabled?()

    case {strategies_requiring_tokens, tokens_enabled?} do
      {[], _} ->
        :ok

      {_, true} ->
        :ok

      {[password | _], false}
      when is_struct(password, Password) and is_map(password.resettable) ->
        {:error,
         DslError.exception(
           path: [:authentication, :tokens, :enabled?],
           message: """
           The `#{password.name}` password authentication strategy requires tokens be enabled because reset tokens are in use.

           To fix this error you can either:

             1. disable password resets by removing the `resettable` configuration from your password strategy, or
             2. enable tokens.
           """
         )}

      {[password | _], false}
      when is_struct(password, Password) and password.sign_in_tokens_enabled? ->
        {:error,
         DslError.exception(
           path: [:authentication, :tokens, :enabled?],
           message: """
           The `#{password.name}` password authentication strategy requires tokens be enabled because sign-in tokens are in use.

           To fix this error you can either:

             1. disable sign in tokens by setting `sign_in_tokens? false` your password strategy, or
             2. enable tokens.
           """
         )}

      {[strategy | _], false} ->
        {:error,
         DslError.exception(
           path: [:authentication, :tokens, :enabled?],
           message: """
           The `#{inspect(strategy.name)}` authentication strategy requires tokens be enabled.

           To fix this error you can either:
             1. disable the `#{inspect(strategy.name)}` strategy, or
             2. enable tokens.
           """
         )}
    end
  end

  @spec is_token_resource(any()) :: boolean() | {boolean(), any()}
  defp is_token_resource(module) when is_atom(module) do
    with true <- function_exported?(module, :spark_is, 0),
         Ash.Resource <- module.spark_is() do
      true
    else
      _ ->
        {false, module}
    end
  end
  defp is_token_resource(_other), do: false

  defp validate_token_resource(dsl_state) do
    if_tokens_enabled(dsl_state, fn dsl_state ->
      with {:ok, resource} when is_truthy(resource) <-
             Info.authentication_tokens_token_resource(dsl_state),
           true <- is_token_resource(resource) do
        :ok
      else
        {:ok, falsy} when is_falsy(falsy) ->
          :ok

        {:error, reason} ->
          {:error, reason}

        {false, bad_token_resource} ->
          {:error,
           DslError.exception(
             path: [:authentication, :tokens, :token_resource],
             message: "`#{bad_token_resource |> bad_token_resource_to_string()}` is not a valid token resource module name"
           )}
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

  # I'm sure this has already been done somewhere else in the Sparkiverse,
  # so maybe this can be removed and replaced by whatever Spark usually uses
  # when logging module names?
  defp bad_token_resource_to_string(module) when is_atom(module) do
    module
    |> to_string()
    |> String.split(".")
    |> tl()
    |> Enum.join(".")
  end
  defp bad_token_resource_to_string(module) when is_binary(module) do
    module
  end
end
