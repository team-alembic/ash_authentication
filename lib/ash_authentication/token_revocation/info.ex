defmodule AshAuthentication.TokenRevocation.Info do
  @moduledoc """
  Generated configuration functions based on a resource's token DSL
  configuration.
  """

  use AshAuthentication.InfoGenerator,
    extension: AshAuthentication.TokenRevocation,
    sections: [:revocation]
end
