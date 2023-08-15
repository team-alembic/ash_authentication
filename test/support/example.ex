defmodule Example do
  @moduledoc false
  use Ash.Api, otp_app: :ash_authentication, extensions: [AshGraphql.Api, AshJsonApi.Api]

  resources do
    resource Example.User
    resource Example.UserWithTokenRequired
    resource Example.Token
    resource Example.UserIdentity
  end

  json_api do
    prefix "/api"
  end
end
