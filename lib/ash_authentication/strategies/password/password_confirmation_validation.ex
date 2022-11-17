defmodule AshAuthentication.Strategy.Password.PasswordConfirmationValidation do
  @moduledoc """
  Validate that the password and password confirmation match.

  This check is only performed when the `confirmation_required?` DSL option is set to `true`.
  """

  use Ash.Resource.Validation
  alias Ash.{Changeset, Error.Changes.InvalidArgument, Error.Framework.AssumptionFailed}

  @doc """
  Validates that the password and password confirmation fields contain
  equivalent values - if confirmation is required.
  """
  @impl true
  @spec validate(Changeset.t(), keyword) :: :ok | {:error, String.t() | Exception.t()}
  def validate(changeset, _) do
    case Map.fetch(changeset.context, :strategy) do
      {:ok, %{confirmation_required?: true} = strategy} ->
        validate_password_confirmation(changeset, strategy)

      {:ok, _} ->
        :ok

      :error ->
        {:error,
         AssumptionFailed.exception(message: "Strategy is missing from the changeset context.")}
    end
  end

  defp validate_password_confirmation(changeset, strategy) do
    password = Changeset.get_argument(changeset, strategy.password_field)
    confirmation = Changeset.get_argument(changeset, strategy.password_confirmation_field)

    if password == confirmation do
      :ok
    else
      {:error,
       InvalidArgument.exception(
         field: strategy.password_confirmation_field,
         message: "does not match"
       )}
    end
  end
end
