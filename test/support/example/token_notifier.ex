# SPDX-FileCopyrightText: 2026 ash_authentication contributors <https://github.com/team-alembic/ash_authentication/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Example.TokenNotifier do
  @moduledoc false
  use Ash.Notifier

  @impl true
  def notify(%{actor: recipient} = notification) when is_pid(recipient) do
    send(recipient, {:token_notification, notification})
    :ok
  end

  def notify(_notification), do: :ok
end
