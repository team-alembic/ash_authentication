defmodule Example.Repo do
  @moduledoc false
  use AshPostgres.Repo, otp_app: :ash_authentication

  @doc false
  def installed_extensions, do: ["uuid-ossp", "citext"]
end
