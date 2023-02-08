defmodule AshAuthentication.UserIdentity.Info do
  @moduledoc """
  Introspection functions for the `AshAuthentication.UserIdentity` Ash
  extension.
  """

  use Spark.InfoGenerator,
    extension: AshAuthentication.UserIdentity,
    sections: [:user_identity]
end
