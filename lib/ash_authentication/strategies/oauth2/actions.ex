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
    api = Info.authentication_api!(strategy.resource)

    strategy.resource
    |> Query.new()
    |> Query.for_read(strategy.sign_in_action_name, params)
    |> api.read(options)
    |> case do
      {:ok, [user]} -> {:ok, user}
      _ -> {:error, Errors.AuthenticationFailed.exception([])}
    end
  end

  @doc """
  Attempt to register a new user.
  """
  @spec register(OAuth2.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def register(%OAuth2{} = strategy, params, options) when strategy.registration_enabled? do
    api = Info.authentication_api!(strategy.resource)
    action = Resource.Info.action(strategy.resource, strategy.register_action_name, :create)

    strategy.resource
    |> Changeset.new()
    |> Changeset.for_create(strategy.register_action_name, params,
      upsert?: true,
      upsert_identity: action.upsert_identity
    )
    |> api.create(options)
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
