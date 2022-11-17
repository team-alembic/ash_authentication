defmodule AshAuthentication.Strategy.Password.ResetTokenValidation do
  @moduledoc """
  Validate that the token is a valid password reset request token.
  """

  use Ash.Resource.Validation
  alias Ash.{Changeset, Error.Changes.InvalidArgument}
  alias AshAuthentication.Jwt

  @doc false
  @impl true
  @spec validate(Changeset.t(), keyword) :: :ok | {:error, Exception.t()}
  def validate(changeset, _) do
    with {:ok, strategy} <- Map.fetch(changeset.context, :strategy),
         token when is_binary(token) <- Changeset.get_argument(changeset, :reset_token),
         {:ok, %{"act" => token_action}, _} <- Jwt.verify(token, changeset.resource),
         {:ok, [resettable]} <- Map.fetch(strategy, :resettable),
         true <- to_string(resettable.password_reset_action_name) == token_action do
      :ok
    else
      _ ->
        {:error, InvalidArgument.exception(field: :reset_token, message: "is not valid")}
    end
  end
end
