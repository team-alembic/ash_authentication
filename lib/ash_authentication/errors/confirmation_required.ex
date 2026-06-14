# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Errors.ConfirmationRequired do
  @moduledoc """
  An OAuth2/OIDC sign-in presented an email matching an existing account, but
  the email could not be trusted to prove ownership.

  Raised internally to abort the sign-in's upsert without mutating the existing
  account. The strategy's `on_untrusted_email_match` is `:confirm`, so the
  caller issues a confirmation to the existing account's email and links the
  provider identity only once the recipient proves ownership.

  The `user`, `user_info` and `oauth_tokens` fields are for internal use by the
  caller that issues the confirmation - they are never surfaced to the end user,
  to avoid leaking which email addresses are registered.
  """
  use Splode.Error,
    fields: [:strategy, :user, :user_info, :oauth_tokens],
    class: :forbidden

  @type t :: Exception.t()

  @impl true
  def message(_), do: "Confirmation required"
end
