defmodule AshAuthExample.Repo do
  @moduledoc false
  use Ecto.Repo,
    otp_app: :ash_auth_example,
    adapter: Ecto.Adapters.Postgres
end
