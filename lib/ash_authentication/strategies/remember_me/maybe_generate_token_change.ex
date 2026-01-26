# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenChange do
  @moduledoc """
  Maybe generate a remember me token and put it in the metadata of the resource to
  later be dropped as a cookie.

  Add this to a sign action to support generating a remember me token.

  Example:

  ```
    create :sign_in_with_magic_link do
      ...
      argument :remember_me, :boolean do
        description "Whether to generate a remember me token."
        allow_nil? true
      end

      change AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenChange
      # change {AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenChange, strategy_name: :remember_me, argument: :remember_me}

      metadata :remember_me_token, :string do
        description "A remember me token that can be used to authenticate the user."
        allow_nil? false
      end
    end
  ```
  """
  use Ash.Resource.Change
  alias Ash.Resource
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt, Utils}

  @impl true
  def change(changeset, options, context) do
    remember_me_argument = Keyword.get(options, :argument, :remember_me)

    if Ash.Changeset.get_argument(changeset, remember_me_argument) do
      change_after_action(changeset, options, context)
    else
      changeset
    end
  end

  defp change_after_action(changeset, options, context) do
    remember_me_strategy_name = Keyword.get(options, :strategy_name, :remember_me)

    case Info.strategy(changeset.resource, remember_me_strategy_name) do
      {:ok, strategy} ->
        changeset
        |> Ash.Changeset.after_action(&generate_token(&1, &2, strategy, context))

      :error ->
        Ash.Changeset.add_error(
          changeset,
          """
          Invalid configuration detected. A remember me token was requested for the #{remember_me_strategy_name} strategy on #{inspect(changeset.resource)},
          but that strategy was not found.
          """
        )
    end
  end

  defp generate_token(changeset, user, strategy, context) do
    extra_claims = changeset.context[:extra_token_claims] || %{}

    claims =
      changeset.context
      |> Map.get(:token_claims, %{})
      |> Map.take(["tenant"])
      |> Map.merge(extra_claims)
      |> Map.put("purpose", "remember_me")

    opts =
      context
      |> Ash.Context.to_opts()
      |> Keyword.put(:purpose, :remember_me)
      |> Keyword.put(:token_lifetime, strategy.token_lifetime)

    case Jwt.token_for_user(user, claims, opts) do
      {:ok, token, _claims} ->
        user_with_meta =
          Resource.put_metadata(user, :remember_me, %{
            token: token,
            cookie_name: strategy.cookie_name,
            max_age: Utils.lifetime_to_seconds(strategy.token_lifetime)
          })

        {:ok, user_with_meta}

      :error ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           query: nil,
           caused_by: %{
             module: __MODULE__,
             action: changeset.action,
             resource: changeset.resource,
             message: "Unable to generate remember me token"
           }
         )}
    end
  end
end
