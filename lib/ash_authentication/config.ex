defmodule AshAuthentication.Config do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration.
  """

  use AshAuthentication.ConfigGenerator,
    extension: AshAuthentication,
    section: :authentication
end
