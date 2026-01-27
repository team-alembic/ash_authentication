# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Errors.SenderFailed do
  @moduledoc """
  A sender failed to deliver a token.
  """
  use Splode.Error,
    fields: [
      sender: nil,
      reason: nil,
      strategy: nil
    ],
    class: :forbidden

  @type t :: Exception.t()

  @impl true
  def message(%{reason: reason}) when not is_nil(reason) do
    "Sender failed: #{inspect(reason)}"
  end

  def message(_), do: "Sender failed"
end
