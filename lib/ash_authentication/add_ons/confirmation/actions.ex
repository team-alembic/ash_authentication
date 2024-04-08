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

  @doc """
  Attempt to confirm a user.
  """
  @spec confirm(Confirmation.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def confirm(strategy, params, opts \\ []) do
    with {:ok, domain} <- Info.domain(strategy.resource),
         {:ok, token} <- Map.fetch(params, "confirm"),
         {:ok, %{"sub" => subject}, _} <- Jwt.verify(token, strategy.resource),
         {:ok, user} <- AshAuthentication.subject_to_user(subject, strategy.resource, opts),
         {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource) do
      user
      |> Changeset.new()
      |> Changeset.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Changeset.for_update(strategy.confirm_action_name, params)
      |> Changeset.after_action(fn _changeset, record ->
        case TokenResource.revoke(token_resource, token) do
          :ok -> {:ok, record}
          {:error, reason} -> {:error, reason}
        end
      end)
      |> domain.update(opts)
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
      |> Stream.map(&{to_string(&1), to_string(Changeset.get_attribute(changeset, &1))})
      |> Map.new()

    with {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource),
         {:ok, domain} <- TokenResource.Info.token_domain(token_resource),
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
           |> Changeset.for_create(store_changes_action, %{
             token: token,
             extra_data: changes,
             purpose: to_string(Strategy.name(strategy))
           })
           |> domain.create(Keyword.merge(opts, upsert?: true)) do
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
         {:ok, domain} <- TokenResource.Info.token_domain(token_resource),
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
           |> domain.read(opts) do
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
end
