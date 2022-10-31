defmodule AshAuthentication.PasswordReset.Info do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration.
  """

  use AshAuthentication.InfoGenerator,
    extension: AshAuthentication.PasswordReset,
    sections: [:password_reset]
end
