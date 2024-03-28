defmodule AshAuthentication.Errors.AuthenticationFailed do
  @moduledoc """
  A generic, authentication failed error.
  """
  use Ash.Error.Exception

  use Splode.Error,
    fields: [
      caused_by: %{},
      changeset: nil,
      field: nil,
      query: nil,
      strategy: nil
    ],
    class: :forbidden

  @type t :: Exception.t()

  def message(_), do: "Authentication failed"

  defimpl Ash.ErrorKind do
    @moduledoc false
    def id(_), do: Ecto.UUID.generate()
    def code(_), do: "authentication_failed"
    def message(_), do: "Authentication failed"
  end
end
