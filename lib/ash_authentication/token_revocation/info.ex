defmodule AshAuthentication.TokenRevocation.Info do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration
  """

  use AshAuthentication.InfoGenerator,
    extension: AshAuthentication.TokenRevocation,
    sections: [:revocation]
end
