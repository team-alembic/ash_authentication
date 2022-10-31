defmodule AshAuthentication.PasswordReset.Notifier do
  @moduledoc """
  This is a moduledoc
  """
  use Ash.Notifier
  alias AshAuthentication.{PasswordReset, PasswordReset.Info}

  @doc false
  @impl true
  def notify(notification) do
    with true <- PasswordReset.enabled?(notification.resource),
         {:ok, action} <- Info.request_password_reset_action_name(notification.resource),
         true <- notification.action.name == action,
         {:ok, {sender, send_opts}} <- Info.sender(notification.resource),
         {:ok, reset_token} <- Map.fetch(notification.data.__metadata__, :reset_token) do
      sender.send(notification.data, reset_token, send_opts)
    end

    :ok
  end
end
