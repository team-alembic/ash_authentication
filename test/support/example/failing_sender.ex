# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.FailingSender do
  @moduledoc """
  A configurable sender for testing sender failure propagation.

  Use `set_failure/1` to configure the sender to return an error,
  and `clear_failure/0` to reset it to success.
  """
  use AshAuthentication.Sender

  @doc "Configure the sender to return an error with the given reason"
  def set_failure(reason) do
    Process.put(:failing_sender_error, reason)
  end

  @doc "Reset the sender to return :ok"
  def clear_failure do
    Process.delete(:failing_sender_error)
  end

  @impl true
  def send(_user, _token, _opts) do
    case Process.get(:failing_sender_error) do
      nil -> :ok
      reason -> {:error, reason}
    end
  end
end
