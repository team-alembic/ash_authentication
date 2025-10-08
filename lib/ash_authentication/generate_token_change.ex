# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.GenerateTokenChange do
  @moduledoc """
  Given a successful registration or sign-in, generate a token.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}
  alias AshAuthentication.{Info, Jwt}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, options, context) do
    changeset
    |> Changeset.after_action(fn changeset, result ->
      {:ok, strategy} = Info.find_strategy(changeset, context, options)

      if Info.authentication_tokens_enabled?(result.__struct__) do
        {:ok, generate_token(changeset.context[:token_type] || :user, result, strategy, context)}
      else
        {:ok, result}
      end
    end)
  end

  @impl true
  def atomic(changeset, options, context) do
    {:ok, change(changeset, options, context)}
  end

  defp generate_token(purpose, record, strategy, context)
       when is_integer(strategy.sign_in_token_lifetime) and purpose == :sign_in do
    {:ok, token, _claims} =
      Jwt.token_for_user(
        record,
        %{"purpose" => to_string(purpose)},
        Ash.Context.to_opts(context,
          token_lifetime: strategy.sign_in_token_lifetime
        ),
        context
      )

    Ash.Resource.put_metadata(record, :token, token)
  end

  defp generate_token(purpose, record, _strategy, context) do
    {:ok, token, _claims} =
      Jwt.token_for_user(record, %{"purpose" => to_string(purpose)}, Ash.Context.to_opts(context))

    Ash.Resource.put_metadata(record, :token, token)
  end
end
