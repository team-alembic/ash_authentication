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
      query
      |> Query.set_context(%{private: %{ash_authentication?: true}})
      |> then(fn query ->
        cond do
          not is_nil(primary_key) ->
            primary_key =
              primary_key
              |> URI.decode_query()
              |> Enum.to_list()

            Query.filter(query, ^primary_key)

          identity = claims["identity"] ->
            identity_field = strategy.identity_field

            Query.filter(query, ^ref(identity_field) == ^identity)

          true ->
            Query.do_filter(query, false)
        end
      end)
      |> Query.after_action(fn
        query, [record] ->
          if strategy.single_use_token? do
            token_resource = Info.authentication_tokens_token_resource!(query.resource)
            :ok = TokenResource.revoke(token_resource, token, Ash.Context.to_opts(context))
          end

          extra_claims =
            case strategy.extra_claims do
              nil -> %{}
              fun when is_function(fun, 4) -> fun.(record, strategy, claims, context)
            end

          {:ok, token, _claims} =
            Jwt.token_for_user(record, extra_claims, Ash.Context.to_opts(context))

          {:ok, [Resource.put_metadata(record, :token, token)]}

        _query, [] ->
          {:ok, []}
      end)
    else
      _error ->
        query
        |> Query.do_filter(false)
        |> maybe_add_error_on_invalid_token()
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
