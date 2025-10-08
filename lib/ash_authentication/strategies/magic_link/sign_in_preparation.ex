# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.MagicLink.SignInPreparation do
  @moduledoc """
  Prepare a query for sign in.
  """

  use Ash.Resource.Preparation
  alias AshAuthentication.{Info, Jwt, TokenResource}
  alias Ash.{Query, Resource, Resource.Preparation}
  require Ash.Query
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

          {:ok, token, _claims} = Jwt.token_for_user(record, %{}, Ash.Context.to_opts(context))
          {:ok, [Resource.put_metadata(record, :token, token)]}

        _query, [] ->
          {:ok, []}
      end)
    else
      _ -> Query.do_filter(query, false)
    end
  end
end
