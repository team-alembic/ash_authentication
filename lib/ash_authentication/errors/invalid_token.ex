defmodule AshAuthentication.Errors.InvalidToken do
  @moduledoc """
  An invalid token was presented.
  """
  use Ash.Error.Exception
  use Splode.Error, fields: [:type], class: :forbidden

  def message(%{type: type}), do: "Invalid #{type} token"

  defimpl Ash.ErrorKind do
    @moduledoc false
    def id(_), do: Ecto.UUID.generate()
    def code(_), do: "invalid_token"
    def message(%{type: nil}), do: "Invalid token"
    def message(%{type: type}), do: "Invalid #{type} token"
  end
end
