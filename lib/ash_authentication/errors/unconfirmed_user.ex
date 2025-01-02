defmodule AshAuthentication.Errors.UnconfirmedUser do
  @moduledoc """
  The user is unconfirmed and so the operation cannot be executed.
  """
  use Splode.Error, fields: [:resource, :field], class: :forbidden

  def message(%{resource: resource}) do
    resource =
      if is_binary(resource) do
        resource
      else
        inspect(resource)
      end

    "`#{resource}` must be confirmed"
  end
end
