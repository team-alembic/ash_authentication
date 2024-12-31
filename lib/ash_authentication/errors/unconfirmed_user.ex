defmodule AshAuthentication.Errors.UnconfirmedUser do
  @moduledoc """
    The user is unconfirmed and so the operation cannot be executed.
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
  def message(_), do: "Unconfirmed user"
end
