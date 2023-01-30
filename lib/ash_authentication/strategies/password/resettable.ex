defmodule AshAuthentication.Strategy.Password.Resettable do
  @moduledoc """
  The entity used to store password reset information.
  """

  defstruct token_lifetime: nil,
            request_password_reset_action_name: nil,
            password_reset_action_name: nil,
            sender: nil

  @type t :: %__MODULE__{
          token_lifetime: hours :: pos_integer,
          request_password_reset_action_name: atom,
          password_reset_action_name: atom,
          sender: {module, keyword}
        }
end
