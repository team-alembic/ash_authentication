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
        extra_claims = changeset.context[:extra_token_claims] || %{}

        {:ok,
         generate_token(
           changeset.context[:token_type] || :user,
           result,
           strategy,
           context,
           extra_claims
         )}
      else
        {:ok, result}
      end
    end)
  end

  @impl true
  def atomic(changeset, options, context) do
    {:ok, change(changeset, options, context)}
  end

  defp generate_token(purpose, record, strategy, context, action_claims)
       when is_integer(strategy.sign_in_token_lifetime) and purpose == :sign_in do
    opts = Ash.Context.to_opts(context, token_lifetime: strategy.sign_in_token_lifetime)
    claims = Map.put(action_claims, "purpose", to_string(purpose))

    {:ok, token, _claims} =
      Jwt.token_for_user(
        record,
        claims,
        opts,
        context
      )

    all_extra_claims = merge_dsl_claims(record, action_claims, opts)

    record
    |> Ash.Resource.put_metadata(:token, token)
    |> maybe_put_claims_metadata(all_extra_claims)
  end

  defp generate_token(purpose, record, _strategy, context, action_claims) do
    opts = Ash.Context.to_opts(context)
    claims = Map.put(action_claims, "purpose", to_string(purpose))

    {:ok, token, _claims} =
      Jwt.token_for_user(record, claims, opts)

    all_extra_claims = merge_dsl_claims(record, action_claims, opts)

    record
    |> Ash.Resource.put_metadata(:token, token)
    |> maybe_put_claims_metadata(all_extra_claims)
  end

  defp merge_dsl_claims(record, action_claims, opts) do
    resource = record.__struct__

    dsl_claims =
      case Info.authentication_tokens_extra_claims(resource) do
        {:ok, extra_claims_fn} when is_function(extra_claims_fn, 2) ->
          case extra_claims_fn.(record, opts) do
            claims when is_map(claims) -> stringify_keys(claims)
            _ -> %{}
          end

        {:ok, extra_claims} when is_map(extra_claims) ->
          stringify_keys(extra_claims)

        _ ->
          %{}
      end

    Map.merge(dsl_claims, action_claims)
  end

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn {k, v} -> {to_string(k), v} end)
  end

  defp maybe_put_claims_metadata(record, extra_claims) when map_size(extra_claims) == 0,
    do: record

  defp maybe_put_claims_metadata(record, extra_claims) do
    Ash.Resource.put_metadata(record, :token_claims, extra_claims)
  end
end
