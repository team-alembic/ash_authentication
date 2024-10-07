defmodule AshAuthentication.Strategy.Password.ResetTokenValidation do
  @moduledoc """
  Validate that the token is a valid password reset request token.
  """

  use Ash.Resource.Validation
  alias Ash.{Changeset, Error.Changes.InvalidArgument, Resource.Validation}
  alias AshAuthentication.{Info, Jwt}

  @doc false
  @impl true
  @spec validate(Changeset.t(), keyword, Validation.Context.t()) :: :ok | {:error, Exception.t()}
  def validate(changeset, _, _) do
    with {:ok, strategy} <- Info.strategy_for_action(changeset.resource, changeset.action.name),
         token when is_binary(token) <- Changeset.get_argument(changeset, :reset_token),
         {:ok, %{"act" => token_action}, _} <- Jwt.verify(token, changeset.resource),
         {:ok, resettable} <- Map.fetch(strategy, :resettable),
         true <- to_string(resettable.password_reset_action_name) == token_action do
      :ok
    else
      _ ->
        {:error, InvalidArgument.exception(field: :reset_token, message: "is not valid")}
    end
  end

  @impl true
  def atomic(changeset, opts, context) do
    validate(changeset, opts, context)
  end
end
