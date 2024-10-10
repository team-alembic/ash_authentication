defmodule AshAuthentication.Errors.CannotConfirmUnconfirmedUser do
  @moduledoc """
  An unconfirmed user cannot be confirmed outside of explicit actions.

  This can be allowed by making an action confirm a user by placing it in the `auto_confirm_actions` list.

  However, it is a security risk to allow unconfirmed users to be confirmed except for via the `confirm` action, invoked with a token.

  See the confirmation tutorial on hexdocs for more.
  """
  use Splode.Error, fields: [:resource], class: :forbidden

  def message(%{resource: resource}) do
    resource =
      if is_binary(resource) do
        resource
      else
        inspect(resource)
      end

    "Could not confirm unconfirmed `#{resource}`."
  end
end
