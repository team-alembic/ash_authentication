defmodule AshAuthentication.Strategy.Confirmation.Actions do
  @moduledoc """
  Actions for the confirmation strategy.

  Provides the code interface for working with resources via confirmation.
  """

  alias Ash.{Changeset, Resource}
  alias AshAuthentication.{Errors.InvalidToken, Info, Jwt, Strategy.Confirmation}

  @doc """
  Attempt to confirm a user.
  """
  @spec confirm(Confirmation.t(), map) :: {:ok, Resource.record()} | {:error, any}
  def confirm(strategy, params) do
    with {:ok, api} <- Info.authentication_api(strategy.resource),
         {:ok, token} <- Map.fetch(params, "confirm"),
         {:ok, %{"sub" => subject}, _} <- Jwt.verify(token, strategy.resource),
         {:ok, user} <- AshAuthentication.subject_to_user(subject, strategy.resource) do
      user
      |> Changeset.new()
      |> Changeset.set_context(%{strategy: strategy})
      |> Changeset.for_update(strategy.confirm_action_name, params)
      |> api.update()
    else
      :error -> {:error, InvalidToken.exception(type: :confirmation)}
      {:error, reason} -> {:error, reason}
    end
  end
end
