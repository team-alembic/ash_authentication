defmodule Example do
  @moduledoc false
  use Ash.Api, otp_app: :ash_authentication

  resources do
    registry Example.Registry
  end
end
