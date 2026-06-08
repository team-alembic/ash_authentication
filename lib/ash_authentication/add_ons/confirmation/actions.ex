# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.Confirmation.Actions do
  @moduledoc """
  Actions for the confirmation add-on.

  Provides the code interface for working with resources via confirmation.
  """

  alias Ash.{Changeset, Error.Framework.AssumptionFailed, Query, Resource}

  alias AshAuthentication.{
    AddOn.Confirmation,
    Errors.InvalidToken,
    Info,
    Jwt,
    Strategy,
    TokenResource
  }

  # Reserved `extra_data` key under which an OAuth2/OIDC identity link is stashed
  # for `on_untrusted_email_match :confirm`. Namespaced so it cannot collide with
  # a monitored field name.
  @oauth_identity_key "__oauth_identity__"

  @doc """
  Attempt to confirm a user.
  """
  @spec confirm(Confirmation.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def confirm(strategy, params, opts \\ []) do
    with {:ok, token} <- Map.fetch(params, "confirm"),
         {:ok, %{"sub" => subject}, _} <- Jwt.verify(token, strategy.resource, opts),
         {:ok, user} <- AshAuthentication.subject_to_user(subject, strategy.resource, opts),
         {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource) do
      opts =
        opts
        |> Keyword.put_new_lazy(:domain, fn ->
          Info.domain!(strategy.resource)
        end)

      user
      |> Changeset.new()
      |> Changeset.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Changeset.for_update(strategy.confirm_action_name, params, opts)
      |> Changeset.after_action(fn _changeset, record ->
        case TokenResource.revoke(token_resource, token, opts) do
          :ok -> {:ok, record}
          {:error, reason} -> {:error, reason}
        end
      end)
      |> Ash.update()
    else
      :error -> {:error, InvalidToken.exception(type: :confirmation)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Store changes in the tokens resource for later re-use.
  """
  @spec store_changes(Confirmation.t(), String.t(), Changeset.t(), keyword) :: :ok | {:error, any}
  def store_changes(strategy, token, changeset, opts \\ []) do
    changes =
      strategy.monitor_fields
      |> Stream.filter(&Changeset.changing_attribute?(changeset, &1))
      |> Enum.reduce_while({:ok, %{}}, fn field, {:ok, acc} ->
        if Keyword.has_key?(changeset.atomics, field) do
          {:halt,
           {:error,
            "Cannot store the changes to the field #{field} because it is being updated atomically."}}
        else
          {:cont,
           {:ok, Map.put(acc, field, to_string(Changeset.get_attribute(changeset, field)))}}
        end
      end)

    with {:ok, changes} <- changes,
         {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource),
         {:ok, domain} <- TokenResource.Info.token_domain(token_resource),
         opts <- opts |> Keyword.put(:upsert?, true) |> Keyword.put_new(:domain, domain),
         {:ok, store_changes_action} <-
           TokenResource.Info.token_confirmation_store_changes_action_name(token_resource),
         {:ok, _token_record} <-
           token_resource
           |> Changeset.new()
           |> Changeset.set_context(%{
             private: %{
               ash_authentication?: true
             }
           })
           |> Changeset.for_create(
             store_changes_action,
             %{
               token: token,
               extra_data: changes,
               purpose: to_string(Strategy.name(strategy))
             },
             opts
           )
           |> Ash.create() do
      :ok
    else
      {:error, reason} ->
        {:error, reason}

      :error ->
        {:error,
         AssumptionFailed.exception(
           message: "Configuration error storing confirmation token data"
         )}
    end
  end

  @doc """
  Get changes from the tokens resource for application.
  """
  @spec get_changes(Confirmation.t(), String.t(), keyword) :: {:ok, map} | :error
  def get_changes(strategy, jti, opts \\ []) do
    with {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource),
         opts <-
           Keyword.put_new_lazy(opts, :domain, fn ->
             TokenResource.Info.token_domain!(token_resource)
           end),
         {:ok, get_changes_action} <-
           TokenResource.Info.token_confirmation_get_changes_action_name(token_resource),
         {:ok, [token_record]} <-
           token_resource
           |> Query.new()
           |> Query.set_context(%{
             private: %{
               ash_authentication?: true
             }
           })
           |> Query.set_context(%{strategy: strategy})
           |> Query.for_read(get_changes_action, %{"jti" => jti})
           |> Ash.read(opts) do
      changes =
        strategy.monitor_fields
        |> Stream.map(&to_string/1)
        |> Stream.map(&{&1, Map.get(token_record.extra_data, &1)})
        |> Stream.reject(&is_nil(elem(&1, 1)))
        |> Map.new()

      {:ok, changes}
    else
      _ -> :error
    end
  end

  @doc """
  Store an OAuth2/OIDC identity link to be applied when the token is confirmed.

  Used by `on_untrusted_email_match :confirm`: `payload` (the provider strategy
  name, `user_info` and `oauth_tokens`) is stashed in the token's server-side
  `extra_data` so that confirming the token links the provider to the account.
  """
  @spec store_identity_link(Confirmation.t(), String.t(), map, keyword) :: :ok | {:error, any}
  def store_identity_link(strategy, token, payload, opts \\ []) do
    with {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource),
         {:ok, domain} <- TokenResource.Info.token_domain(token_resource),
         opts <- opts |> Keyword.put(:upsert?, true) |> Keyword.put_new(:domain, domain),
         {:ok, store_changes_action} <-
           TokenResource.Info.token_confirmation_store_changes_action_name(token_resource),
         {:ok, _token_record} <-
           token_resource
           |> Changeset.new()
           |> Changeset.set_context(%{
             private: %{
               ash_authentication?: true
             }
           })
           |> Changeset.for_create(
             store_changes_action,
             %{
               token: token,
               extra_data: %{@oauth_identity_key => payload},
               purpose: to_string(Strategy.name(strategy))
             },
             opts
           )
           |> Ash.create() do
      :ok
    else
      {:error, reason} ->
        {:error, reason}

      :error ->
        {:error,
         AssumptionFailed.exception(
           message: "Configuration error storing confirmation identity link"
         )}
    end
  end

  @doc """
  Get a stored OAuth2/OIDC identity link for application when confirming.
  """
  @spec get_identity_link(Confirmation.t(), String.t(), keyword) :: {:ok, map} | :error
  def get_identity_link(strategy, jti, opts \\ []) do
    with {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource),
         opts <-
           Keyword.put_new_lazy(opts, :domain, fn ->
             TokenResource.Info.token_domain!(token_resource)
           end),
         {:ok, get_changes_action} <-
           TokenResource.Info.token_confirmation_get_changes_action_name(token_resource),
         {:ok, [token_record]} <-
           token_resource
           |> Query.new()
           |> Query.set_context(%{
             private: %{
               ash_authentication?: true
             }
           })
           |> Query.set_context(%{strategy: strategy})
           |> Query.for_read(get_changes_action, %{"jti" => jti})
           |> Ash.read(opts),
         payload when is_map(payload) <- Map.get(token_record.extra_data, @oauth_identity_key) do
      {:ok, payload}
    else
      _ -> :error
    end
  end
end
