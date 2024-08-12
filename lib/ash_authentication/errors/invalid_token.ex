defmodule AshAuthentication.Errors.InvalidToken do
  @moduledoc """
  An invalid token was presented.
  """
  use Splode.Error, fields: [:type], class: :forbidden

  def message(%{type: type}), do: "Invalid #{type} token"
end
