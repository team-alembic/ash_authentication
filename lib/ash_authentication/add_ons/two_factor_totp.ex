defmodule AshAuthentication.AddOn.TwoFactorTotp do
  @moduledoc """
  Support for two-factor authentication, using Time-Based One-Time Passwords (TOTP).
  """

  defstruct name: :two_factor_totp,
            storage_field: nil,
            verify_action_name: nil,
            issuer: nil,
            resource: nil,
            strategy_module: __MODULE__,
            provider: :two_factor_totp

  use AshAuthentication.Strategy.Custom, style: :add_on, entity: __MODULE__.Dsl.dsl()
end
