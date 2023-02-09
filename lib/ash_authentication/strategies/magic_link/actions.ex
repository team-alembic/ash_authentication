defmodule AshAuthentication.Strategy.MagicLink.Actions do
  @moduledoc """
  Actions for the magic link strategy.

  Provides the code interface for working with user resources for providing
  magic links.
  """

  alias Ash.{Query, Resource}
  alias AshAuthentication.{Errors, Info, Strategy.MagicLink}

  @doc """
  Request a magic link for a user.
  """
  @spec request(MagicLink.t(), map, keyword) :: :ok | {:error, any}
  def request(strategy, params, options) do
    api = Info.authentication_api!(strategy.resource)

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> Query.for_read(strategy.request_action_name, params)
    |> api.read(options)
    |> case do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Attempt to sign a user in via magic link.
  """
  @spec sign_in(MagicLink.t(), map, keyword) ::
          {:ok, Resource.record()} | {:error, Errors.AuthenticationFailed.t()}
  def sign_in(strategy, params, options) do
    api = Info.authentication_api!(strategy.resource)

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> Query.for_read(strategy.sign_in_action_name, params)
    |> api.read(options)
    |> case do
      {:ok, [user]} ->
        {:ok, user}

      {:ok, []} ->
        {:error,
         Errors.AuthenticationFailed.exception(
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
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned too many users"
           }
         )}

      {:error, error} when is_exception(error) ->
        {:error, Errors.AuthenticationFailed.exception(caused_by: error)}

      {:error, error} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned error: #{inspect(error)}"
           }
         )}
    end
  end
end
