defmodule AshAuthentication.Errors.AuthenticationFailed do
  @moduledoc """
  A generic, authentication failed error.
  """
  use Ash.Error.Exception
  def_ash_error([], class: :forbidden)

  @type t :: Exception.t()

  defimpl Ash.ErrorKind do
    @moduledoc false
    def id(_), do: Ecto.UUID.generate()
    def code(_), do: "authentication_failed"
    def message(_), do: "Authentication failed"
  end
end
