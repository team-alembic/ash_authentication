defmodule AshAuthentication.Confirmation.Info do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration.
  """

  use AshAuthentication.InfoGenerator,
    extension: AshAuthentication.Confirmation,
    sections: [:confirmation]
end
