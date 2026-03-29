defmodule AshAuthentication.Strategy.WebAuthn.Verifier do
  @moduledoc """
  DSL verifier for the WebAuthn strategy.

  Validates configuration at compile time.
  """

  alias AshAuthentication.Strategy.WebAuthn
  alias Spark.Error.DslError

  @doc false
  @spec verify(WebAuthn.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with :ok <- validate_rp_id(strategy),
         :ok <- validate_credential_resource(strategy),
         :ok <- validate_tokens_enabled(dsl_state) do
      :ok
    end
  end

  defp validate_rp_id(%{rp_id: rp_id}) when is_binary(rp_id) do
    cond do
      String.starts_with?(rp_id, "http://") or String.starts_with?(rp_id, "https://") ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, :webauthn],
           message:
             "rp_id must be a domain name without protocol prefix (e.g. \"example.com\", not \"https://example.com\")"
         )}

      String.contains?(rp_id, "/") ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, :webauthn],
           message:
             "rp_id must be a domain name without paths (e.g. \"example.com\", not \"example.com/auth\")"
         )}

      true ->
        :ok
    end
  end

  defp validate_rp_id(_), do: :ok

  defp validate_credential_resource(%{credential_resource: nil}) do
    {:error,
     DslError.exception(
       path: [:authentication, :strategies, :webauthn],
       message: "credential_resource is required"
     )}
  end

  defp validate_credential_resource(_), do: :ok

  defp validate_tokens_enabled(dsl_state) do
    if AshAuthentication.Info.authentication_tokens_enabled?(dsl_state) do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:authentication, :strategies, :webauthn],
         message: """
         The WebAuthn strategy requires tokens to be enabled.

         Add the following to your authentication block:

             authentication do
               tokens do
                 enabled? true
                 token_resource YourApp.Accounts.Token
                 signing_secret YourApp.Secrets
               end
             end
         """
       )}
    end
  end
end
