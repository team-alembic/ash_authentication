defmodule AshAuthentication.Errors.MissingSecret do
  @moduledoc """
  A secret is now missing.
  """
  use Ash.Error.Exception
  use Splode.Error, fields: [:resource], class: :forbidden

  def message(%{path: path, resource: resource}) do
    "Secret for `#{Enum.join(path, ".")}` on the `#{inspect(resource)}` resource is not accessible."
  end

  defimpl Ash.ErrorKind do
    @moduledoc false
    def id(_), do: Ecto.UUID.generate()
    def code(_), do: "missing_secret"

    def message(%{path: path, resource: resource}),
      do:
        "Secret for `#{Enum.join(path, ".")}` on the `#{inspect(resource)}` resource is not accessible."
  end
end
