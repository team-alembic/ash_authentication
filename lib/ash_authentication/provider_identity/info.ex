defmodule AshAuthentication.ProviderIdentity.Info do
  @moduledoc """
  Generated configuration functions based on a resource's token DSL
  configuration.
  """

  use AshAuthentication.InfoGenerator,
    extension: AshAuthentication.ProviderIdentity,
    sections: [:provider_identity]
end
