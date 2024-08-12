defmodule AshAuthentication.Errors.MissingSecret do
  @moduledoc """
  A secret is now missing.
  """
  use Splode.Error, fields: [:resource], class: :forbidden

  def message(%{path: path, resource: resource}) do
    "Secret for `#{Enum.join(path, ".")}` on the `#{inspect(resource)}` resource is not accessible."
  end
end
