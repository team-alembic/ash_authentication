defmodule AshAuthentication.Strategy.Password.Verifier do
  @moduledoc """
  DSL verifier for the password strategy.
  """

  alias AshAuthentication.{HashProvider, Info, Sender, Strategy.Password}
  alias Spark.{Dsl.Verifier, Error.DslError}
  import AshAuthentication.Validations

  @doc false
  @spec verify(Password.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with :ok <- validate_behaviour(strategy.hash_provider, HashProvider),
         :ok <- validate_tokens_enabled_for_sign_in_tokens(dsl_state, strategy),
         :ok <- validate_tokens_enabled_for_resettable(dsl_state, strategy) do
      maybe_validate_resettable_sender(dsl_state, strategy)
    end
  end

  defp validate_tokens_enabled_for_sign_in_tokens(dsl_state, strategy)
       when strategy.sign_in_tokens_enabled? do
    resource = Verifier.get_persisted(dsl_state, :module)

    cond do
      !strategy.sign_in_enabled? ->
        {:error,
         DslError.exception(
           module: resource,
           path: [
             :authentication,
             :strategies,
             :password,
             strategy.name,
             :sign_in_tokens_enabled?
           ],
           message: """
           The `sign_in_tokens_enabled?` option requires that `sign_in_enabled?` be set to `true`.
           """
         )}

      !Info.authentication_tokens_enabled?(dsl_state) ->
        {:error,
         DslError.exception(
           module: resource,
           path: [
             :authentication,
             :strategies,
             :password,
             strategy.name,
             :sign_in_tokens_enabled?
           ],
           message: """
           The `sign_in_tokens_enabled?` option requires that tokens are enabled for your resource. For example:


              authentication do
                ...

                tokens do
                  enabled? true
                end
              end
           """
         )}

      true ->
        :ok
    end
  end

  defp validate_tokens_enabled_for_sign_in_tokens(_, _), do: :ok

  defp validate_tokens_enabled_for_resettable(dsl_state, %{resettable: resettable, name: name})
       when is_struct(resettable) do
    resource = Verifier.get_persisted(dsl_state, :module)

    if Info.authentication_tokens_enabled?(dsl_state) do
      :ok
    else
      {:error,
       DslError.exception(
         module: resource,
         path: [
           :authentication,
           :strategies,
           :password,
           name,
           :resettable
         ],
         message: """
         The `resettable` option requires that tokens are enabled for your resource. For example:


            authentication do
              ...

              tokens do
                enabled? true
              end
            end
         """
       )}
    end
  end

  defp validate_tokens_enabled_for_resettable(_, _), do: :ok

  defp maybe_validate_resettable_sender(dsl_state, %{resettable: resettable})
       when is_struct(resettable) do
    with {:ok, {sender, _opts}} <- Map.fetch(resettable, :sender),
         :ok <- validate_behaviour(sender, Sender) do
      :ok
    else
      :error ->
        resource = Verifier.get_persisted(dsl_state, :module)

        {:error,
         DslError.exception(
           module: resource,
           path: [:authentication, :strategies, :password, :resettable],
           message: "A `sender` is required."
         )}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_validate_resettable_sender(_, _), do: :ok
end
