defmodule AshAuthentication.Identity.Config do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration.
  """

  use AshAuthentication.ConfigGenerator,
    extension: AshAuthentication.Identity,
    section: :identity_authentication
end
