defmodule Example do
  @moduledoc false
  use Ash.Domain, otp_app: :ash_authentication, extensions: [AshGraphql.Domain, AshJsonApi.Domain]

  resources do
    resource Example.User
    resource Example.UserWithTokenRequired
    resource Example.Token
    resource Example.UserIdentity
    resource Example.UserWithRegisterMagicLink
  end

  json_api do
    prefix "/api"
  end
end
