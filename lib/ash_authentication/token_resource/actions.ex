defmodule AshAuthentication.TokenResource.Actions do
  @moduledoc """
  The code interface for interacting with the token resource.
  """

  alias Ash.{Changeset, DataLayer, Query, Resource}
  alias AshAuthentication.{TokenResource, TokenResource.Info}

  import AshAuthentication.Utils

  @doc false
  @spec read_expired(Resource.t(), keyword) :: {:ok, [Resource.record()]} | {:error, any}
  def read_expired(resource, opts \\ []) do
    with :ok <- assert_resource_has_extension(resource, TokenResource),
         {:ok, api} <- Info.token_api(resource),
         {:ok, read_expired_action_name} <- Info.token_read_expired_action_name(resource) do
      resource
      |> Query.new()
      |> Query.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Query.for_read(read_expired_action_name, opts)
      |> api.read()
    end
  end

  @doc """
  Remove all expired records.
  """
  @spec expunge_expired(Resource.t(), keyword) :: :ok | {:error, any}
  def expunge_expired(resource, opts \\ []) do
    case Info.token_expunge_expired_action_name(resource) do
      {:ok, expunge_expired_action_name} ->
        resource
        |> DataLayer.transaction(
          fn -> expunge_inside_transaction(resource, expunge_expired_action_name, opts) end,
          nil,
          %{
            type: :bulk_destroy,
            metadata: %{
              metadata: %{
                resource: resource,
                action: expunge_expired_action_name
              }
            }
          }
        )
        |> case do
          {:ok, :ok} -> :ok
          {:error, reason} -> {:error, reason}
        end

      :error ->
        {:error, "No configured expunge_expired_action_name"}
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
         {:ok, api} <- Info.token_api(resource),
         {:ok, is_revoked_action_name} <- Info.token_revocation_is_revoked_action_name(resource) do
      resource
      |> Query.new()
      |> Query.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Query.for_read(is_revoked_action_name, %{"token" => token}, opts)
      |> api.read()
      |> case do
        {:ok, []} -> false
        {:ok, _} -> true
        _ -> false
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
         {:ok, api} <- Info.token_api(resource),
         {:ok, is_revoked_action_name} <- Info.token_revocation_is_revoked_action_name(resource) do
      resource
      |> Query.new()
      |> Query.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Query.for_read(is_revoked_action_name, %{"jti" => jti}, opts)
      |> api.read()
      |> case do
        {:ok, []} -> false
        {:ok, _} -> true
        _ -> false
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
  """
  @spec revoke(Resource.t(), String.t(), keyword) :: :ok | {:error, any}
  def revoke(resource, token, opts \\ []) do
    with :ok <- assert_resource_has_extension(resource, TokenResource),
         {:ok, api} <- Info.token_api(resource),
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
        Keyword.merge(opts, upsert?: true)
      )
      |> api.create()
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
         {:ok, api} <- Info.token_api(resource),
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
      |> api.create()
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
         {:ok, api} <- Info.token_api(resource),
         {:ok, get_token_action_name} <- Info.token_get_token_action_name(resource) do
      resource
      |> Query.for_read(get_token_action_name, params, opts)
      |> api.read()
    end
  end

  defp expunge_inside_transaction(resource, expunge_expired_action_name, opts) do
    with :ok <- assert_resource_has_extension(resource, TokenResource),
         {:ok, api} <- Info.token_api(resource),
         {:ok, read_expired_action_name} <- Info.token_read_expired_action_name(resource),
         query <-
           resource |> Query.new() |> Query.set_context(%{private: %{ash_authentication?: true}}),
         query <- Query.for_read(query, read_expired_action_name, opts),
         {:ok, expired} <- api.read(query) do
      Enum.reduce_while(expired, :ok, fn record, :ok ->
        record
        |> Changeset.new()
        |> Changeset.set_context(%{
          private: %{
            ash_authentication?: true
          }
        })
        |> Changeset.for_destroy(expunge_expired_action_name, opts)
        |> api.destroy()
        |> case do
          :ok -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
    end
  end
end
