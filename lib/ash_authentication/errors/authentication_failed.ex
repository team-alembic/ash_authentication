defmodule AshAuthentication.Errors.AuthenticationFailed do
  @moduledoc """
  A generic, authentication failed error.
  """
  use Splode.Error,
    fields: [
      caused_by: %{},
      changeset: nil,
      field: nil,
      query: nil,
      strategy: nil
    ],
    class: :forbidden

  alias AshAuthentication.Debug

  @type t :: Exception.t()

  @impl true
  def exception(args) do
    args
    |> super()
    |> Debug.describe()
  end

  @impl true
  def message(_), do: "Authentication failed"
end
