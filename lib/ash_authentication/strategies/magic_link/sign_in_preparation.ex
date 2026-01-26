# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.MagicLink.SignInPreparation do
  @moduledoc """
  Prepare a query for sign in.
  """

  use Ash.Resource.Preparation
  alias Ash.{Query, Resource, Resource.Preparation}
  alias AshAuthentication.{Errors, Info, Jwt, TokenResource}
  require Ash.Query
  require Logger
  import Ash.Expr

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _opts, context) do
    subject_name =
      query.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    with {:ok, strategy} <- Info.strategy_for_action(query.resource, query.action.name),
         token when is_binary(token) <- Query.get_argument(query, strategy.token_param_name),
         {:ok, %{"act" => token_action, "sub" => subject} = claims, _} <-
           Jwt.verify(token, query.resource, Ash.Context.to_opts(context)),
         ^token_action <- to_string(strategy.sign_in_action_name),
         %URI{path: ^subject_name, query: primary_key} <- URI.parse(subject) do
      prepare_valid_token_query(query, strategy, claims, primary_key, token, context)
    else
      _error ->
        query
        |> Query.do_filter(false)
        |> maybe_add_error_on_invalid_token()
    end
  end

  defp prepare_valid_token_query(query, strategy, claims, primary_key, token, context) do
    query
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> filter_by_identity(primary_key, claims, strategy)
    |> Query.after_action(&handle_sign_in_result(&1, &2, strategy, claims, token, context))
  end

  defp filter_by_identity(query, primary_key, _claims, _strategy) when not is_nil(primary_key) do
    primary_key =
      primary_key
      |> URI.decode_query()
      |> Enum.to_list()

    Query.filter(query, ^primary_key)
  end

  defp filter_by_identity(query, _primary_key, %{"identity" => identity}, strategy) do
    Query.filter(query, ^ref(strategy.identity_field) == ^identity)
  end

  defp filter_by_identity(query, _primary_key, _claims, _strategy) do
    Query.do_filter(query, false)
  end

  defp handle_sign_in_result(query, [record], strategy, claims, token, context) do
    revoke_single_use_token!(strategy, query, token, context)
    generate_token_for_record(record, query, strategy, claims, context)
  end

  defp handle_sign_in_result(_query, [], _strategy, _claims, _token, _context) do
    {:ok, []}
  end

  defp revoke_single_use_token!(strategy, query, token, context) do
    if strategy.single_use_token? do
      token_resource = Info.authentication_tokens_token_resource!(query.resource)
      :ok = TokenResource.revoke(token_resource, token, Ash.Context.to_opts(context))
    end
  end

  defp generate_token_for_record(record, query, strategy, claims, context) do
    query_extra_claims = query.context[:extra_token_claims] || %{}

    strategy_extra_claims =
      case strategy.extra_claims do
        nil -> %{}
        fun when is_function(fun, 4) -> fun.(record, strategy, claims, context)
      end

    all_extra_claims = Map.merge(strategy_extra_claims, query_extra_claims)

    case Jwt.token_for_user(record, all_extra_claims, Ash.Context.to_opts(context)) do
      {:ok, token, _claims} -> {:ok, [Resource.put_metadata(record, :token, token)]}
      {:error, error} -> {:error, error}
    end
  end

  defp maybe_add_error_on_invalid_token(query) do
    return_error =
      Application.get_env(:ash_authentication, :return_error_on_invalid_magic_link_token?)

    if is_nil(return_error) && Info.strategy_present?(query.resource, :audit_log) do
      Logger.warning("""
      return_error_on_invalid_magic_link_token? is not set and the AshAuthentication audit_log add-on is present.

      The backward compatible behaviour is for the query to be successful and return an empty list if the token is
      invalid. This will be logged as a success in the audit log even though the sign in failed.

      The new behaviour is to return an error and log the sign in attempt as a failure in the audit log. In the
      next major version this will be the default behaviour.

      To suppress this warning, set return_error_on_invalid_magic_link_token? in your config:
      config :ash_authentication, return_error_on_invalid_magic_link_token?: true
      """)
    end

    if return_error do
      query |> add_error_on_invalid_token()
    else
      query
    end
  end

  defp add_error_on_invalid_token(query) do
    {:ok, strategy} = Info.strategy_for_action(query.resource, query.action.name)

    Query.after_action(query, fn query, _result ->
      {:error,
       Errors.AuthenticationFailed.exception(
         strategy: strategy,
         query: query,
         caused_by:
           Errors.InvalidToken.exception(
             field: strategy.token_param_name,
             reason: "Token did not pass verification",
             type: :magic_link
           )
       )}
    end)
  end
end
