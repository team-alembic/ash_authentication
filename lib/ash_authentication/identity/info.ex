defmodule AshAuthentication.Identity.Info do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration.
  """

  use AshAuthentication.InfoGenerator,
    extension: AshAuthentication.Identity,
    sections: [:identity_authentication]
end
