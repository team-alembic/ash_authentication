defmodule Example do
  @moduledoc false
  use Ash.Api, otp_app: :ash_authentication, extensions: [AshGraphql.Api, AshJsonApi.Api]

  resources do
    registry Example.Registry
  end

  json_api do
    prefix "/api"
  end
end
