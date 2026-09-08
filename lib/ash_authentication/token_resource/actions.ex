# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.TokenResource.Actions do
  @moduledoc """
  The code interface for interacting with the token resource.
  """

  alias Ash.{Changeset, Error.Changes.StaleRecord, Query, Resource}
  alias AshAuthentication.{Errors.InvalidToken, TokenResource, TokenResource.Info}

  import Ash.Expr
  import AshAuthentication.Utils

  require Logger

  @doc false
  @spec read_expired(Resource.t(), keyword) :: {:ok, [Resource.record()]} | {:error, any}
  def read_expired(resource, opts \\ []) do
    with :ok <- assert_resource_has_extension(resource, TokenResource),
         {:ok, domain} <- Info.token_domain(resource),
         {:ok, read_expired_action_name} <- Info.token_read_expired_action_name(resource) do
      resource
      |> Query.new()
      |> Query.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Query.for_read(read_expired_action_name, opts)
      |> Ash.read(domain: domain)
    end
  end

  @doc """
  Remove all expired records.
  """
  @spec expunge_expired(Resource.t(), keyword) :: :ok | {:error, any}
  def expunge_expired(resource, opts \\ []) do
    expunge_expired_action_name = Info.token_expunge_expired_action_name!(resource)

    with :ok <- assert_resource_has_extension(resource, TokenResource),
         {:ok, read_expired_action_name} <- Info.token_read_expired_action_name(resource) do
      opts =
        opts
        |> Keyword.put_new_lazy(:domain, fn -> Info.token_domain!(resource) end)

      authorize_with =
        if Ash.DataLayer.data_layer_can?(resource, :expr_error) do
          :error
        else
          :filter
        end

      resource
      |> Query.new()
      |> Query.set_context(%{private: %{ash_authentication?: true}})
      |> Query.for_read(read_expired_action_name, %{}, opts)
      |> Ash.bulk_destroy(
        expunge_expired_action_name,
        %{},
        opts
        |> Keyword.update(
          :context,
          %{private: %{ash_authentication?: true}},
          &Ash.Helpers.deep_merge_maps(&1, %{private: %{ash_authentication?: true}})
        )
        |> Keyword.merge(
          strategy: [:atomic, :atomic_batches, :stream],
          return_errors?: true,
          notify?: true,
          return_records?: false,
          return_notifications?: false,
          authorize_with: authorize_with
        )
      )
      |> case do
        %{status: :success} -> :ok
        %{errors: errors} -> {:error, Ash.Error.to_class(errors)}
      end
    end
  end

  @doc """
  Has the token been revoked?

  Similar to `jti_revoked?/2..3` except that it extracts the JTI from the token,
  rather than relying on it to be passed in.
  """
  @spec token_revoked?(Resource.t(), String.t(), keyword) :: boolean
  def token_revoked?(resource, token, opts \\ []) do
    with :ok <- assert_resource_has_extension(resource, TokenResource),
         {:ok, domain} <- Info.token_domain(resource),
         {:ok, is_revoked_action_name} <- Info.token_revocation_is_revoked_action_name(resource),
         action when not is_nil(action) <-
           Ash.Resource.Info.action(resource, is_revoked_action_name) do
      case action.type do
        :action ->
          resource
          |> Ash.ActionInput.for_action(
            is_revoked_action_name,
            %{"token" => token},
            Keyword.put(opts, :domain, domain)
          )
          |> Ash.ActionInput.set_context(%{
            private: %{
              ash_authentication?: true
            }
          })
          |> Ash.run_action()
          |> case do
            {:ok, value} ->
              value

            {:error, error} ->
              Logger.error("""
              Error while checking if token is revoked.
              We must assume that it is revoked for security purposes.

              #{Exception.format(:error, error)}
              """)

              true
          end

        :read ->
          resource
          |> Query.new()
          |> Query.set_context(%{
            private: %{
              ash_authentication?: true
            }
          })
          |> Query.for_read(
            is_revoked_action_name,
            %{"token" => token},
            Keyword.put(opts, :domain, domain)
          )
          |> Ash.read()
          |> case do
            {:ok, []} ->
              false

            {:ok, _} ->
              true

            {:error, error} ->
              Logger.error("""
              Error while checking if token is revoked.
              We must assume that it is revoked for security purposes.

              #{Exception.format(:error, error)}
              """)

              true
          end
      end
    end
  end

  @doc """
  Has the token been revoked?

  Similar to `token-revoked?/2..3` except that rather than extracting the JTI
  from the token, assumes that it's being passed in directly.
  """
  @spec jti_revoked?(Resource.t(), String.t(), keyword) :: boolean
  def jti_revoked?(resource, jti, opts \\ []) do
    with :ok <- assert_resource_has_extension(resource, TokenResource),
         {:ok, domain} <- Info.token_domain(resource),
         {:ok, is_revoked_action_name} <- Info.token_revocation_is_revoked_action_name(resource),
         action when not is_nil(action) <-
           Ash.Resource.Info.action(resource, is_revoked_action_name) do
      case action.type do
        :action ->
          resource
          |> Ash.ActionInput.for_action(
            is_revoked_action_name,
            %{"jti" => jti},
            Keyword.take(Keyword.put(opts, :domain, domain), [
              :actor,
              :authorize?,
              :context,
              :tenant,
              :tracer,
              :domain
            ])
          )
          |> Ash.ActionInput.set_context(%{
            private: %{
              ash_authentication?: true
            }
          })
          |> Ash.run_action()
          |> case do
            {:ok, value} ->
              value

            {:error, error} ->
              Logger.error("""
              Error while checking if token is revoked.
              We must assume that it is revoked for security purposes.

              #{Exception.format(:error, error)}
              """)

              true
          end

        :read ->
          resource
          |> Query.new()
          |> Query.set_context(%{
            private: %{
              ash_authentication?: true
            }
          })
          |> Query.for_read(
            is_revoked_action_name,
            %{"jti" => jti},
            Keyword.take(Keyword.put(opts, :domain, domain), [
              :actor,
              :authorize?,
              :context,
              :tenant,
              :tracer,
              :domain
            ])
          )
          |> Ash.read()
          |> case do
            {:ok, []} ->
              false

            {:ok, _} ->
              true

            {:error, error} ->
              Logger.error("""
              Error while checking if token is revoked.
              We must assume that it is revoked for security purposes.

              #{Exception.format(:error, error)}
              """)

              true
          end
      end
    end
  end

  @doc false
  @spec valid_jti?(Resource.t(), String.t(), keyword) :: boolean
  def valid_jti?(resource, jti, opts \\ []), do: !jti_revoked?(resource, jti, opts)

  @doc """
  Revoke a token.

  Extracts the JTI from the provided token and uses it to generate a revocation
  record.

  The caller must verify the token before it calls this function.  The token
  resource cannot verify a token itself.

  ## Options

    * `:single_use?` — set this when the token grants something that exactly one
      caller may claim, such as a single-use magic link. The revocation is then
      performed by a conditional upsert which only matches a row whose purpose
      is not already `"revocation"`. The data layer evaluates the condition as
      part of the write, so it is the serialisation point: of several concurrent
      revocations exactly one matches a row and the rest get
      `{:error, %AshAuthentication.Errors.InvalidToken{type: :revocation}}`.
      Callers on a read action get this guarantee too, because it does not
      depend on an enclosing transaction.

      Defaults to `false`, which performs an unconditional upsert. That is
      idempotent rather than exclusive: revoking an already revoked token
      returns `:ok`. Leave it unset where losing the race is harmless, such as
      signing out, where the winner revokes the token and the wanted end state
      is reached either way.
  """
  @spec revoke(Resource.t(), String.t(), keyword) :: :ok | {:error, any}
  def revoke(resource, token, opts \\ []) do
    {single_use?, opts} = Keyword.pop(opts, :single_use?, false)

    with :ok <- assert_resource_has_extension(resource, TokenResource),
         {:ok, domain} <- Info.token_domain(resource),
         {:ok, revoke_token_action_name} <-
           Info.token_revocation_revoke_token_action_name(resource) do
      resource
      |> Changeset.new()
      |> Changeset.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Changeset.for_create(
        revoke_token_action_name,
        %{"token" => token},
        Keyword.merge(opts, revocation_opts(single_use?))
      )
      |> Ash.create(domain: domain)
      |> case do
        {:ok, record} -> revocation_result(record)
        {:error, reason} -> {:error, translate_revocation_conflict(reason)}
      end
    end
  end

  # A stored token record already carries a trustworthy `expires_at`, written
  # when this library minted the token.  Both clauses only flip the purpose, so
  # that a claim read from the token cannot rewrite that value.
  defp revocation_opts(false), do: [upsert?: true, upsert_fields: [:purpose]]

  defp revocation_opts(true),
    do: [
      upsert?: true,
      upsert_fields: [:purpose],
      upsert_condition: expr(purpose != "revocation"),
      return_skipped_upsert?: true
    ]

  # A single-use revocation that lost the race matches no row. Asking for the
  # skipped upsert to be returned rather than raised keeps the outcome a value
  # in both callers: on a read action there is no transaction to roll back, and
  # on a create action the caller turns this into a changeset error, which
  # aborts the action and rolls it back with a meaningful reason attached.
  defp revocation_result(record) do
    if Resource.get_metadata(record, :upsert_skipped) do
      {:error, revocation_conflict()}
    else
      :ok
    end
  end

  defp translate_revocation_conflict(%Ash.Error.Invalid{errors: errors} = error) do
    if Enum.any?(errors, &match?(%StaleRecord{}, &1)) do
      revocation_conflict()
    else
      error
    end
  end

  defp translate_revocation_conflict(error), do: error

  defp revocation_conflict,
    do: InvalidToken.exception(type: :revocation, reason: "token has already been revoked")

  @doc """
  Revoke a token by JTI.

  If you have the token, you should use `revoke/2` instead.
  """
  @spec revoke_jti(Resource.t(), String.t(), String.t(), keyword) ::
          :ok | {:error, any}
  def revoke_jti(resource, jti, subject, opts \\ []) do
    with :ok <- assert_resource_has_extension(resource, TokenResource),
         {:ok, domain} <- Info.token_domain(resource),
         {:ok, revoke_token_action_name} <-
           Info.token_revocation_revoke_jti_action_name(resource) do
      resource
      |> Changeset.new()
      |> Changeset.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Changeset.for_create(
        revoke_token_action_name,
        %{"jti" => jti, "subject" => subject},
        Keyword.merge(opts, upsert?: true)
      )
      |> Ash.create(domain: domain)
      |> case do
        {:ok, _} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @doc """
  Store a token.

  Stores a token for any purpose.
  """
  @spec store_token(Resource.t(), map, keyword) :: :ok | {:error, any}
  def store_token(resource, params, opts \\ []) do
    with :ok <- assert_resource_has_extension(resource, TokenResource),
         {:ok, domain} <- Info.token_domain(resource),
         {:ok, store_token_action_name} <- Info.token_store_token_action_name(resource) do
      resource
      |> Changeset.new()
      |> Changeset.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Changeset.for_create(
        store_token_action_name,
        params,
        Keyword.merge(opts, upsert?: true)
      )
      |> Ash.create(domain: domain)
      |> case do
        {:ok, _} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @doc """
  Retrieve a token by token or JTI optionally filtering by purpose.
  """
  @spec get_token(Resource.t(), map, keyword) :: {:ok, [Resource.record()]} | {:error, any}
  def get_token(resource, params, opts \\ []) do
    with :ok <- assert_resource_has_extension(resource, TokenResource),
         {:ok, domain} <- Info.token_domain(resource),
         {:ok, get_token_action_name} <- Info.token_get_token_action_name(resource) do
      resource
      |> Query.new()
      |> Query.set_context(%{private: %{ash_authentication?: true}})
      |> Query.for_read(
        get_token_action_name,
        params,
        Keyword.take(Keyword.put(opts, :domain, domain), [
          :actor,
          :authorize?,
          :tenant,
          :tracer,
          :domain
        ])
      )
      |> Ash.read()
    end
  end
end
