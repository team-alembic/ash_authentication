defmodule AshAuthentication.PasswordAuthentication.PasswordConfirmationValidation do
  @moduledoc """
  Validate that the password and password confirmation match.

  This check is only performed when the `confirmation_required?` DSL option is set to `true`.
  """

  use Ash.Resource.Validation
  alias Ash.{Changeset, Error.Changes.InvalidArgument}
  alias AshAuthentication.PasswordAuthentication.Info

  @doc """
  Validates that the password and password confirmation fields contain
  equivalent values - if confirmation is required.
  """
  @impl true
  @spec validate(Changeset.t(), keyword) :: :ok | {:error, String.t() | Exception.t()}
  def validate(changeset, _) do
    with true <- Info.password_authentication_confirmation_required?(changeset.resource),
         {:ok, password_field} <- Info.password_authentication_password_field(changeset.resource),
         {:ok, confirm_field} <-
           Info.password_authentication_password_confirmation_field(changeset.resource),
         password <- Changeset.get_argument(changeset, password_field),
         confirmation <- Changeset.get_argument(changeset, confirm_field),
         false <- password == confirmation do
      {:error, InvalidArgument.exception(field: confirm_field, message: "does not match")}
    else
      :error -> {:error, "Password confirmation required, but not configured"}
      _ -> :ok
    end
  end
end
