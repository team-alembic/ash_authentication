defmodule AshAuthentication.Info do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration.
  """

  use AshAuthentication.InfoGenerator,
    extension: AshAuthentication,
    sections: [:authentication, :tokens],
    prefix?: true
end
