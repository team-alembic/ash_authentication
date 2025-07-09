defmodule ExampleMultiTenant do
  @moduledoc false
  use Ash.Domain, otp_app: :ash_authentication

  resources do
    resource ExampleMultiTenant.Organisation
    resource ExampleMultiTenant.User
    resource ExampleMultiTenant.GlobalUser
    resource ExampleMultiTenant.UserWithTokenRequired
    resource ExampleMultiTenant.Token
    resource ExampleMultiTenant.UserIdentity
    resource ExampleMultiTenant.UserWithRegisterMagicLink
    resource ExampleMultiTenant.ApiKey
  end
end
