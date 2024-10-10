defmodule AshAuthentication.Strategy.OAuth2.Verifier do
  @moduledoc """
  DSL verifier for oauth2 strategies.
  """

  alias AshAuthentication.Strategy.OAuth2
  alias Spark.Error.DslError
  import AshAuthentication.Validations

  @doc false
  @spec verify(OAuth2.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with :ok <- validate_secret(strategy, :authorize_url),
         :ok <- validate_secret(strategy, :client_id),
         :ok <- validate_secret(strategy, :client_secret),
         :ok <- validate_secret(strategy, :redirect_uri),
         :ok <- validate_secret(strategy, :base_url),
         :ok <- validate_secret(strategy, :token_url),
         :ok <- validate_secret(strategy, :user_url),
         :ok <- prevent_hijacking(dsl_state, strategy) do
      if strategy.auth_method == :private_key_jwt do
        validate_secret(strategy, :private_key)
      else
        :ok
      end
    end
  end

  defp prevent_hijacking(_dsl_state, %{prevent_hijacking?: false}), do: :ok
  defp prevent_hijacking(_dsl_state, %{registration_enabled?: false}), do: :ok

  defp prevent_hijacking(dsl_state, strategy) do
    case Enum.find(
           AshAuthentication.Info.authentication_strategies(dsl_state),
           fn other_strategy ->
             other_strategy.__struct__ == AshAuthentication.Strategy.Password &&
               other_strategy.registration_enabled?
           end
         ) do
      nil ->
        :ok

      password_strategy ->
        if has_confirmation_add_on?(dsl_state, password_strategy) do
          :ok
        else
          {:error,
           DslError.exception(
             path: [:authentication, :strategies, strategy.name],
             message: """
             If you have an oauth2 strategy and a password strategy, you must also have a
             confirmation add-on that monitors the password's identity field.

             This is to prevent from account hijacking. If the field used in your password strategy is not
             an email field, you can set `prevent_hijacking?: false` in your oauth strategy.

             For more information, see the confirmation tutorial on hexdocs.
             """
           )}
        end
    end
  end

  defp has_confirmation_add_on?(dsl_state, password_strategy) do
    Enum.any?(AshAuthentication.Info.authentication_add_ons(dsl_state), fn add_on ->
      add_on.__struct__ == AshAuthentication.AddOn.Confirmation &&
        password_strategy.identity_field in add_on.monitor_fields
    end)
  end
end
