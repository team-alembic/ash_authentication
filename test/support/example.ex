defmodule Example do
  @moduledoc false
  use Ash.Domain, otp_app: :ash_authentication, extensions: [AshGraphql.Domain, AshJsonApi.Domain]

  resources do
    resource Example.Token
    resource Example.User
    resource Example.UserIdentity
    resource Example.UserWithMultitenancy
    resource Example.UserWithRegisterMagicLink
    resource Example.UserWithTokenRequired
  end

  json_api do
    prefix "/api"
  end
end
