defmodule AshAuthentication.TokenResource.Info do
  @moduledoc """
  Introspection functions for the `AshAuthentication.TokenResource` Ash
  extension.
  """

  use Spark.InfoGenerator,
    extension: AshAuthentication.TokenResource,
    sections: [:token]
end
