# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.LogOutEverywhere.Transformer do
  @moduledoc """
  DSL transformer the the log-out-everywhere add-on.

  Ensures that there is only ever one present and that it is correctly
  configured.
  """

  alias Ash.Resource
  alias AshAuthentication.AddOn.LogOutEverywhere
  alias AshAuthentication.AddOn.LogOutEverywhere.OnPasswordChange
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Strategy.Custom.Helpers

  @doc false
  @spec transform(LogOutEverywhere.t(), map) ::
          {:ok, LogOutEverywhere.t() | map} | {:error, Exception.t()}
  def transform(strategy, dsl) do
    with :ok <-
           validate_token_generation_enabled(
             dsl,
             "Token generation must be enabled for log-out-everywhere to work."
           ),
         {:ok, dsl} <-
           maybe_build_action(dsl, strategy.action_name, &build_log_out_action(&1, strategy)),
         :ok <- validate_log_out_action(dsl, strategy),
         {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, dsl} <- maybe_add_apply_on_password_change_change(dsl, strategy) do
      strategy = %{strategy | resource: resource}

      dsl =
        dsl
        |> then(&register_strategy_actions([strategy.action_name], &1, strategy))
        |> put_add_on(strategy)

      {:ok, dsl}
    else
      {:error, reason} when is_binary(reason) ->
        {:error,
         DslError.exception(
           module: Transformer.get_persisted(dsl, :module),
           path: [:authentication, :add_ons, :log_out_everywhere],
           message: reason
         )}

      {:error, reason} ->
        {:error, reason}

      :error ->
        {:error,
         DslError.exception(
           module: Transformer.get_persisted(dsl, :module),
           path: [:authentication, :add_ons, :log_out_everywhere],
           message: "Configuration error"
         )}
    end
  end

  defp build_log_out_action(dsl, strategy) do
    with {:ok, token_resource} <-
           AshAuthentication.Info.authentication_tokens_token_resource(dsl),
         {:ok, argument} <-
           Transformer.build_entity(Resource.Dsl, [:actions, :action], :argument,
             allow_nil?: false,
             description: "The user to log out",
             name: strategy.argument_name,
             public?: true,
             type: :struct,
             constraints: [
               instance_of: Transformer.get_persisted(dsl, :module)
             ]
           ) do
      Transformer.build_entity(Resource.Dsl, [:actions], :action,
        arguments: [argument],
        name: strategy.action_name,
        run: LogOutEverywhere.Action,
        touches_resources: [strategy.resource, token_resource]
      )
    end
  end

  defp validate_log_out_action(dsl, strategy) do
    with {:ok, action} <- validate_action_exists(dsl, strategy.action_name),
         :ok <- validate_action_option(action, :type, [:action]),
         :ok <- validate_action_option(action, :returns, [nil]),
         :ok <-
           validate_action_option(action, :run, [
             LogOutEverywhere.Action,
             {LogOutEverywhere.Action, []}
           ]),
         :ok <- validate_action_has_argument(action, strategy.argument_name),
         :ok <-
           validate_action_argument_option(action, strategy.argument_name, :type, [
             Ash.Type.Struct
           ]) do
      validate_action_argument_option(action, strategy.argument_name, :allow_nil?, [false])
    end
  end

  defp maybe_add_apply_on_password_change_change(dsl, strategy)
       when strategy.apply_on_password_change? != true,
       do: {:ok, dsl}

  defp maybe_add_apply_on_password_change_change(dsl, _strategy) do
    dsl
    |> get_all_password_strategies()
    |> Enum.map(& &1.hashed_password_field)
    |> Enum.reduce_while({:ok, dsl}, fn hashed_password_field, {:ok, dsl} ->
      case maybe_build_password_change_change(dsl, hashed_password_field) do
        {:ok, dsl} -> {:cont, {:ok, dsl}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp get_all_password_strategies(dsl) do
    dsl
    |> AshAuthentication.Info.authentication_strategies()
    |> Enum.filter(&is_struct(&1, AshAuthentication.Strategy.Password))
  end

  defp maybe_build_password_change_change(dsl, hashed_password_field) do
    dsl
    |> matching_changes(OnPasswordChange,
      on: [:update],
      where: [{Ash.Resource.Validation.Changing, [field: hashed_password_field, touching?: true]}]
    )
    |> case do
      [] -> build_password_change_change(dsl, hashed_password_field)
      _ -> {:ok, dsl}
    end
  end

  defp build_password_change_change(dsl, hashed_password_field) do
    with {:ok, change} <-
           Transformer.build_entity(Resource.Dsl, [:changes], :change,
             change: {OnPasswordChange, []},
             on: [:update],
             where: [
               {Ash.Resource.Validation.Changing, [field: hashed_password_field, touching?: true]}
             ]
           ) do
      {:ok, Transformer.add_entity(dsl, [:changes], change)}
    end
  end

  defp matching_changes(dsl, module, options) do
    dsl
    |> Resource.Info.changes()
    |> Enum.filter(fn
      %{change: {^module, _}} = change -> all_change_options_match?(change, options)
      %{change: ^module} = change -> all_change_options_match?(change, options)
      _ -> false
    end)
  end

  defp all_change_options_match?(change, options) do
    options
    |> Enum.all?(fn {key, value} ->
      Map.get(change, key) == value
    end)
  end
end
