defmodule AshAuthentication.TokenRevocation.Info do
  @moduledoc """
  Introspection functions for the `AshAuthentication.TokenRevocation` Ash
  extension.
  """

  use AshAuthentication.InfoGenerator,
    extension: AshAuthentication.TokenRevocation,
    sections: [:revocation]
end
