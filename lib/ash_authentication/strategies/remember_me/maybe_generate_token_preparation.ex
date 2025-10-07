# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation do
  @moduledoc """
  Maybe generate a remember me token and put it in the metadata of the resource to
  later be dropped as a cookie.

  Add this to a sign action to support generating a remember me token.

  Example:

  ```
    read :sign_in do
      ...
      argument :remember_me, :boolean do
        description "Whether to generate a remember me token."
        allow_nil? true
      end

      prepare AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation
      # prepare {AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation, strategy_name: :remember_me, argument: :remember_me}

      metadata :remember_me_token, :string do
        description "A remember me token that can be used to authenticate the user."
        allow_nil? false
      end
    end
  ```
  """
  use Ash.Resource.Preparation
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt, Utils}
  alias Ash.{Error.Unknown, Query, Resource, Resource.Preparation}
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, options, context) do
    remember_me_argument = Keyword.get(options, :argument, :remember_me)

    case Query.get_argument(query, remember_me_argument) do
      true ->
        prepare_after_action(query, options, context)

      _ ->
        query
    end
  end

  defp prepare_after_action(query, options, context) do
    remember_me_strategy_name = Keyword.get(options, :strategy_name, :remember_me)

    case Info.strategy(query.resource, remember_me_strategy_name) do
      {:ok, strategy} ->
        query
        |> Query.after_action(&verify_result(&1, &2, strategy, context))

      :error ->
        Query.add_error(
          query,
          Unknown.exception(
            message: """
            Invalid configuration detected. A remember me token was requested for the #{remember_me_strategy_name} strategy on #{inspect(query.resource)},
            but that strategy was not found.
            """
          )
        )
    end
  end

  defp verify_result(query, [user], strategy, context) do
    claims =
      query.context
      |> Map.get(:token_claims, %{})
      |> Map.take(["tenant"])
      |> Map.put("purpose", "remember_me")

    opts =
      context
      |> Ash.Context.to_opts()
      |> Keyword.put(:purpose, :remember_me)
      |> Keyword.put(:token_lifetime, strategy.token_lifetime)

    case Jwt.token_for_user(user, claims, opts) do
      {:ok, token, _claims} ->
        user =
          Resource.put_metadata(user, :remember_me, %{
            token: token,
            cookie_name: strategy.cookie_name,
            max_age: Utils.lifetime_to_seconds(strategy.token_lifetime)
          })

        {:ok, [user]}

      :error ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           query: query,
           caused_by: %{
             module: __MODULE__,
             action: query.action,
             resource: query.resource,
             message: "Unable to generate remember me token"
           }
         )}
    end
  end

  defp verify_result(query, _resource, _strategy, _context) do
    {:ok, query}
  end
end
