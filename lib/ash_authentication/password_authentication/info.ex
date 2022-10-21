defmodule AshAuthentication.PasswordAuthentication.Info do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration.
  """

  use AshAuthentication.InfoGenerator,
    extension: AshAuthentication.PasswordAuthentication,
    sections: [:password_authentication]
end
