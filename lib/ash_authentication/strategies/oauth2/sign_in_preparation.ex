# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.SignInPreparation do
  @moduledoc """
  Prepare a query for sign in

  Performs three main tasks:

    1. Ensures that there is only one matching user record returned, otherwise
       returns an authentication failed error.
    2. Generates an access token if token generation is enabled.
    3. Updates the user identity resource, if one is enabled.

  ## Attaching a new provider identity

  The sign-in action's filter decides which account a callback matches. When the
  provider's `iss`/`sub` is not yet linked to that account, this preparation
  decides whether to link it:

    * If a different identity for this strategy already belongs to the account -
      refuse. One account cannot have two identities for the same provider
      auto-linked.
    * If the strategy trusts the provider's `email_verified` claim **and** the
      verified email equals the account's `email_field` - link.
    * Otherwise refuse. The person must sign in with their existing method to
      link the provider.

  The email comparison is what makes the trusted claim mean something. A verified
  `email_verified` claim attests ownership of one address and nothing else, so on
  an action filtered by a username it says nothing about the account the filter
  matched. `AshAuthentication.Strategy.OAuth2.UserResolver` states the same rule
  for the register action, where the matched `upsert_identity` values carry the
  evidence instead.

  An account whose `email_field` is empty, or a provider that supplies no email,
  therefore never links here. So does a resource with no email attribute, which
  is why `trust_email_verified?` requires `email_field` to name one.
  """
  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt, UserIdentity}
  alias AshAuthentication.Strategy.OAuth2
  alias AshAuthentication.Strategy.OAuth2.UserResolver
  require Ash.Query
  import AshAuthentication.Utils, only: [is_falsy: 1]

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, opts, context) do
    case Info.find_strategy(query, context, opts) do
      :error ->
        {:error,
         AuthenticationFailed.exception(
           strategy: :unknown,
           query: query,
           caused_by: %{
             module: __MODULE__,
             action: query.action,
             message: "Unable to infer strategy"
           }
         )}

      {:ok, strategy} ->
        opts = [tenant: context.tenant, actor: context.actor]

        query
        |> Query.after_action(fn
          query, [user] ->
            with :ok <- verify_identity(user, query, strategy, opts),
                 {:ok, user} <- maybe_update_identity(user, query, strategy, opts) do
              {:ok, [maybe_generate_token(user, context)]}
            end

          _, _ ->
            {:error,
             AuthenticationFailed.exception(
               strategy: strategy,
               query: query,
               caused_by: %{
                 module: __MODULE__,
                 action: query.action,
                 strategy: strategy,
                 message: "Query should return a single user"
               }
             )}
        end)
    end
  end

  defp verify_identity(_user, _query, strategy, _opts) when is_falsy(strategy.identity_resource),
    do: :ok

  defp verify_identity(user, query, strategy, opts) do
    user_info = Query.get_argument(query, :user_info)

    case OAuth2.uid_from_user_info(user_info) do
      nil ->
        identity_error(query, strategy, "Provider did not return a stable `sub`/`uid` claim")

      uid ->
        verify_resolved_identity(user, query, strategy, user_info, uid, opts)
    end
  end

  defp verify_resolved_identity(user, query, strategy, user_info, uid, opts) do
    case UserResolver.fetch_identity(strategy, uid, opts) do
      {:ok, identity} ->
        if identity_belongs_to?(identity, user, strategy) do
          :ok
        else
          identity_error(query, strategy, "Identity is linked to a different user")
        end

      :error ->
        cond do
          UserResolver.has_identity_for_strategy?(strategy, user, opts) ->
            identity_error(
              query,
              strategy,
              "A different #{strategy.name} identity is already linked to this account"
            )

          UserResolver.email_trusted?(strategy, user_info) and
              UserResolver.email_matches_account?(strategy, user, user_info) ->
            :ok

          true ->
            identity_error(
              query,
              strategy,
              "Email could not be verified against the account this sign-in matches"
            )
        end
    end
  end

  defp identity_belongs_to?(identity, user, strategy) do
    {:ok, user_id_attribute_name} =
      UserIdentity.Info.user_identity_user_id_attribute_name(strategy.identity_resource)

    [pk] = Ash.Resource.Info.primary_key(strategy.resource)

    Map.get(identity, user_id_attribute_name) == Map.get(user, pk)
  end

  defp identity_error(query, strategy, message) do
    {:error,
     AuthenticationFailed.exception(
       strategy: strategy,
       query: query,
       caused_by: %{
         module: __MODULE__,
         action: query.action,
         strategy: strategy,
         message: message
       }
     )}
  end

  defp maybe_update_identity(user, _query, strategy, _opts)
       when is_falsy(strategy.identity_resource),
       do: {:ok, user}

  defp maybe_update_identity(user, query, strategy, opts) do
    strategy.identity_resource
    |> UserIdentity.Actions.upsert(
      %{
        user_info: Query.get_argument(query, :user_info),
        oauth_tokens: Query.get_argument(query, :oauth_tokens),
        strategy: strategy.name,
        user_id: user.id
      },
      opts
    )
    |> case do
      {:ok, _identity} ->
        user
        |> Ash.load(
          [
            {strategy.identity_relationship_name,
             Query.new(strategy.identity_resource)
             |> Query.set_context(%{
               private: %{
                 ash_authentication?: true
               }
             })}
          ],
          Keyword.put(opts, :domain, Info.domain!(strategy.resource))
        )

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_generate_token(user, context) do
    if AshAuthentication.Info.authentication_tokens_enabled?(user.__struct__) do
      {:ok, token, _claims} = Jwt.token_for_user(user, %{}, Ash.Context.to_opts(context))
      %{user | __metadata__: Map.put(user.__metadata__, :token, token)}
    else
      user
    end
  end
end
