defmodule AshAuthentication.Strategy.OAuth2.Actions do
  @moduledoc """
  Actions for the oauth2 strategy.

  Provides the code interface for working with resources via an OAuth2 strategy.
  """

  alias Ash.{Changeset, Error.Invalid.NoSuchAction, Query, Resource}
  alias AshAuthentication.{Errors, Info, Strategy.OAuth2}

  @doc """
  Attempt to sign in a user.
  """
  @spec sign_in(OAuth2.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def sign_in(%OAuth2{} = strategy, _params, _options) when strategy.registration_enabled?,
    do:
      {:error,
       NoSuchAction.exception(
         resource: strategy.resource,
         action: strategy.sign_in_action_name,
         type: :read
       )}

  def sign_in(%OAuth2{} = strategy, params, options) do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Query.for_read(strategy.sign_in_action_name, params, options)
    |> Ash.read()
    |> case do
      {:ok, [user]} ->
        {:ok, user}

      {:ok, []} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned no users"
           }
         )}

      {:ok, _users} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned too many users"
           }
         )}

      {:error, error} when is_struct(error, Errors.AuthenticationFailed) ->
        {:error, error}

      {:error, error} when is_exception(error) ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: error
         )}

      {:error, error} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned error: #{inspect(error)}"
           }
         )}
    end
  end

  @doc """
  Attempt to register a new user.
  """
  @spec register(OAuth2.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def register(%OAuth2{} = strategy, params, options) when strategy.registration_enabled? do
    action = Resource.Info.action(strategy.resource, strategy.register_action_name, :create)

    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> Changeset.new()
    |> Changeset.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Changeset.for_create(
      strategy.register_action_name,
      params,
      Keyword.merge(options,
        upsert?: true,
        upsert_identity: action.upsert_identity
      )
    )
    |> Ash.create()
  end

  def register(%OAuth2{} = strategy, _params, _options),
    do:
      {:error,
       NoSuchAction.exception(
         resource: strategy.resource,
         action: strategy.register_action_name,
         type: :create
       )}
end
