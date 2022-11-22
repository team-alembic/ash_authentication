defmodule AshAuthentication.Errors.InvalidToken do
  @moduledoc """
  An invalid token was presented.
  """
  use Ash.Error.Exception
  def_ash_error([:type], class: :forbidden)

  defimpl Ash.ErrorKind do
    @moduledoc false
    def id(_), do: Ecto.UUID.generate()
    def code(_), do: "invalid_token"
    def message(%{type: nil}), do: "Invalid token"
    def message(%{type: type}), do: "Invalid #{type} token"
  end
end
