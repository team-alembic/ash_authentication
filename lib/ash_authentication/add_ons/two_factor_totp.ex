defmodule AshAuthentication.AddOn.TwoFactorTotp do
  @moduledoc """
  Support for two-factor authentication, using Time-Based One-Time Passwords (TOTP).
  """

  defstruct name: :two_factor_totp,
            storage_field: nil,
            identity_field: nil,
            verify_action_name: nil,
            issuer: nil,
            resource: nil

  use AshAuthentication.Strategy.Custom, style: :add_on, entity: __MODULE__.Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: __MODULE__.Transformer
end
