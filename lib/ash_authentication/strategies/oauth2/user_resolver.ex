# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.UserResolver do
  @moduledoc """
  Resolves which local user an OAuth2/OIDC sign-in belongs to.

  Per OpenID Connect Core only the `iss`/`sub` claim combination uniquely and
  stably identifies an end-user, so matching is driven by the user identity
  resource - **never** by the email address.

  Given the changeset for an OAuth2/OIDC register (upsert) action, the rules are:

    1. If an identity already exists for this `(strategy, sub)`, the sign-in
       belongs to that user. The changeset's upsert keys are rewritten to that
       user's values so the upsert resolves to them (and the provider cannot
       change a user's email).

    2. Otherwise (a `sub` not seen before):
       * If no local account has the provider's email - proceed (a new account
         is created; if the email is not trusted and a confirmation add-on is
         present, that add-on gates it).
       * If an account with that email already has an identity for this strategy
         (a *different* `sub`) - reject. A single account cannot have two
         identities for the same provider auto-linked.
       * If the strategy's `email_verified` claim can be trusted
         (`trust_email_verified?` and the claim is true) - link the sign-in to
         that account.
       * Otherwise the email cannot be trusted to prove ownership. With
         `on_untrusted_email_match :reject` (the default) the sign-in is
         rejected and the user must sign in with their existing method to link
         the provider. With `on_untrusted_email_match :confirm` the upsert is
         aborted with a `ConfirmationRequired` error so the caller can issue a
         confirmation to the existing account's email and link the provider
         only once the recipient proves ownership.

  Rejections are surfaced as a generic `AuthenticationFailed` error to avoid
  leaking which email addresses are registered.
  """

  alias Ash.Changeset

  alias AshAuthentication.{
    Errors.AuthenticationFailed,
    Errors.ConfirmationRequired,
    Info,
    Strategy.OAuth2,
    UserIdentity
  }

  require Ash.Query

  @doc false
  @spec resolve(Changeset.t(), OAuth2.t(), keyword) :: Changeset.t()
  def resolve(changeset, strategy, opts \\ []) do
    user_info = Changeset.get_argument(changeset, :user_info)

    case OAuth2.uid_from_user_info(user_info) do
      nil ->
        reject(changeset, strategy, "Provider did not return a stable `sub`/`uid` claim")

      uid ->
        case fetch_identity(strategy, uid, opts) do
          {:ok, identity} -> coerce_to_existing_user(changeset, strategy, identity, opts)
          :error -> resolve_new_identity(changeset, strategy, user_info, opts)
        end
    end
  end

  defp resolve_new_identity(changeset, strategy, user_info, opts) do
    case fetch_user_by_upsert_identity(changeset, strategy, opts) do
      :error ->
        # No local account has this email - allow the upsert to create one.
        changeset

      {:ok, user} ->
        cond do
          has_identity_for_strategy?(strategy, user, opts) ->
            reject(
              changeset,
              strategy,
              "A different #{strategy.name} identity is already linked to this account"
            )

          email_trusted?(strategy, user_info) ->
            # Verified email matches an existing account - link to it. The email
            # already matches so the upsert resolves to this user.
            changeset

          strategy.on_untrusted_email_match == :confirm ->
            require_confirmation(changeset, strategy, user, user_info)

          true ->
            reject(
              changeset,
              strategy,
              "Email could not be verified and an account with this email already exists"
            )
        end
    end
  end

  defp require_confirmation(changeset, strategy, user, user_info) do
    # Abort the upsert without touching the existing account. The caller issues
    # a confirmation to the existing account's email and links the provider only
    # once the recipient proves ownership.
    Changeset.add_error(
      changeset,
      ConfirmationRequired.exception(
        strategy: strategy,
        user: user,
        user_info: user_info,
        oauth_tokens: Changeset.get_argument(changeset, :oauth_tokens)
      )
    )
  end

  defp coerce_to_existing_user(changeset, strategy, identity, opts) do
    case load_identity_user(strategy, identity, opts) do
      {:ok, user} ->
        Enum.reduce(upsert_identity_keys(changeset), changeset, fn key, changeset ->
          Changeset.force_change_attribute(changeset, key, Map.get(user, key))
        end)

      :error ->
        # Orphaned identity (user no longer exists) - fall back to the upsert.
        changeset
    end
  end

  @doc false
  @spec fetch_identity(OAuth2.t(), String.t(), keyword) :: {:ok, Ash.Resource.record()} | :error
  def fetch_identity(strategy, uid, opts \\ []) do
    cfg = UserIdentity.Info.user_identity_options(strategy.identity_resource)

    strategy.identity_resource
    |> base_query(opts)
    |> Ash.Query.do_filter([
      {cfg.strategy_attribute_name, to_string(strategy.name)},
      {cfg.uid_attribute_name, uid}
    ])
    |> read_one(identity_domain(strategy), opts)
  end

  defp load_identity_user(strategy, identity, opts) do
    cfg = UserIdentity.Info.user_identity_options(strategy.identity_resource)
    user_id = Map.get(identity, cfg.user_id_attribute_name)

    strategy.resource
    |> base_query(opts)
    |> Ash.Query.do_filter([{user_pk(strategy), user_id}])
    |> read_one(Info.domain!(strategy.resource), opts)
  end

  defp fetch_user_by_upsert_identity(changeset, strategy, opts) do
    keys = upsert_identity_keys(changeset)
    values = Enum.map(keys, &{&1, Changeset.get_attribute(changeset, &1)})

    if keys == [] or Enum.any?(values, fn {_key, value} -> is_nil(value) end) do
      :error
    else
      strategy.resource
      |> base_query(opts)
      |> Ash.Query.do_filter(values)
      |> read_one(Info.domain!(strategy.resource), opts)
    end
  end

  @doc false
  @spec has_identity_for_strategy?(OAuth2.t(), Ash.Resource.record(), keyword) :: boolean
  def has_identity_for_strategy?(strategy, user, opts \\ []) do
    cfg = UserIdentity.Info.user_identity_options(strategy.identity_resource)

    strategy.identity_resource
    |> base_query(opts)
    |> Ash.Query.do_filter([
      {cfg.strategy_attribute_name, to_string(strategy.name)},
      {cfg.user_id_attribute_name, Map.get(user, user_pk(strategy))}
    ])
    |> read_one(identity_domain(strategy), opts)
    |> case do
      {:ok, _identity} -> true
      :error -> false
    end
  end

  @doc false
  @spec email_trusted?(OAuth2.t(), map) :: boolean
  def email_trusted?(%{trust_email_verified?: true}, user_info) do
    Map.get(user_info, "email_verified", Map.get(user_info, :email_verified)) in [true, "true"]
  end

  def email_trusted?(_strategy, _user_info), do: false

  defp upsert_identity_keys(changeset) do
    with name when not is_nil(name) <- changeset.action.upsert_identity,
         identity when not is_nil(identity) <-
           Ash.Resource.Info.identity(changeset.resource, name) do
      identity.keys
    else
      _ -> []
    end
  end

  defp user_pk(strategy) do
    [pk] = Ash.Resource.Info.primary_key(strategy.resource)
    pk
  end

  defp identity_domain(strategy) do
    {:ok, domain} = UserIdentity.Info.user_identity_domain(strategy.identity_resource)
    domain
  end

  defp base_query(resource, opts) do
    resource
    |> Ash.Query.new()
    |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
    |> maybe_set_tenant(opts[:tenant])
  end

  defp maybe_set_tenant(query, nil), do: query
  defp maybe_set_tenant(query, tenant), do: Ash.Query.set_tenant(query, tenant)

  defp read_one(query, domain, opts) do
    case Ash.read(query, domain: domain, actor: opts[:actor]) do
      {:ok, [record | _]} -> {:ok, record}
      _ -> :error
    end
  end

  defp reject(changeset, strategy, message) do
    Changeset.add_error(
      changeset,
      AuthenticationFailed.exception(
        strategy: strategy,
        changeset: changeset,
        caused_by: %{
          module: __MODULE__,
          strategy: strategy,
          action: changeset.action.name,
          message: message
        }
      )
    )
  end
end
