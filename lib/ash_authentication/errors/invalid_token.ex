# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Errors.InvalidToken do
  @moduledoc """
  An invalid token was presented.
  """
  use Splode.Error, fields: [:type, :field, :reason], class: :forbidden

  def message(%{type: type, reason: reason}) do
    if reason do
      "Invalid #{type} token: #{reason}"
    else
      "Invalid #{type} token"
    end
  end
end
