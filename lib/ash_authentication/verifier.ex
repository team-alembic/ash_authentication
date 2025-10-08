# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Verifier do
  @moduledoc """
  The Authentication verifier.

  Checks configuration constraints after compile.
  """

  use Spark.Dsl.Verifier
  alias AshAuthentication.{AddOn.Confirmation, Info, Strategy, Strategy.Password}
  alias Spark.{Dsl.Transformer, Dsl.Verifier, Error.DslError}
  import AshAuthentication.Utils

  @doc false
  @impl true
  @spec verify(map) ::
          :ok
          | {:error, term}
          | {:warn, String.t() | list(String.t())}
  def verify(dsl_state) do
    with {:ok, _domain} <- validate_domain_presence(dsl_state),
         :ok <- validate_tokens_may_be_required(dsl_state),
         :ok <- validate_confirmation_action_names(dsl_state) do
      if Info.authentication_tokens_enabled?(dsl_state) and
           Info.authentication_session_identifier!(dsl_state) == :error and
           not Info.authentication_tokens_require_token_presence_for_authentication?(dsl_state) do
        {:error,
         DslError.exception(
           path: [:authentication, :session_identifier],
           message: """
           Must set `authentication.session_identifier` to either `:jti` or `:unsafe`,
           unless `authentication.tokens.require_token_presence_for_authentication?` is set to `true`.

           If you are seeing this error while upgrading ash_authentication, be aware that
           updating this setting will log out all of your users.

           When set to `:unsafe`, tokens are not revoked when the user logs out.
           When set to `:jti`, we use this information to revoke tokens on logout.

           We suggest setting `authentication.tokens.require_token_presence_for_authentication?` to `true`
           to ensure that tokens are always present during authentication, which makes this option unnecessary.
           Changing either of these settings will log out all of your users.
           """
         )}
      else
        validate_token_resource(dsl_state)
      end
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

             1. disable sign in tokens by setting `sign_in_tokens_enabled? false` your password strategy, or
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

  @spec token_resource?(any()) :: {boolean(), any()}
  defp token_resource?(module) do
    {Spark.Dsl.is?(module, Ash.Resource), module}
  end

  defp validate_token_resource(dsl_state) do
    if_tokens_enabled(dsl_state, fn dsl_state ->
      with {:ok, resource} when is_truthy(resource) <-
             Info.authentication_tokens_token_resource(dsl_state),
           {true, _resource} <- token_resource?(resource) do
        :ok
      else
        {:ok, falsy} when is_falsy(falsy) ->
          :ok

        {false, bad_token_resource} ->
          {:error,
           DslError.exception(
             path: [:authentication, :tokens, :token_resource],
             message: "`#{inspect(bad_token_resource)}` is not a valid token resource module name"
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

  defp validate_confirmation_action_names(dsl_state) do
    conflicting_strategies =
      dsl_state
      |> Info.authentication_add_ons()
      |> Enum.filter(&is_struct(&1, Confirmation))
      |> Enum.frequencies_by(& &1.confirm_action_name)
      |> Enum.reject(&(elem(&1, 1) == 1))

    case conflicting_strategies do
      [] ->
        :ok

      conflicts ->
        conflicting_action_names = Enum.map(conflicts, &elem(&1, 0))

        conflicting_strategy_names =
          dsl_state
          |> Info.authentication_add_ons()
          |> Enum.filter(
            &(is_struct(&1, Confirmation) and &1.confirm_action_name in conflicting_action_names)
          )
          |> Enum.map(& &1.name)

        {:error,
         DslError.exception(
           module: Verifier.get_persisted(dsl_state, :module),
           path: [:authentication, :add_ons],
           message: """
           Multiple confirmation add-ons are configured with conflicting action names.

           The following confirmation strategies have conflicting action names:
            #{Enum.map_join(conflicting_strategy_names, "\n", &"  - #{inspect(&1)}")}
           All confirmation add-ons must have unique action names. You can fix this by:
           1. Giving each confirmation add-on a unique name (e.g., `confirmation :confirm_email` and `confirmation :confirm_phone`)
           2. Or explicitly setting different `confirm_action_name` values for each add-on

           Example:
           ```elixir
           add_ons do
             confirmation :confirm_email do
               monitor_fields [:email]
               # ... other config
             end

             confirmation :confirm_phone do
               monitor_fields [:phone]
               # ... other config
             end
           end
           ```
           """
         )}
    end
  end
end
