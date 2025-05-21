defmodule AshAuthentication.AddOn.TwoFactorTotp do
  @moduledoc """
  Support for two-factor authentication, using Time-Based One-Time Passwords (TOTP).
  """

  # TODO: Write all of the docs for the things
  # TODO: Write Igniter to set up add-on in end-user apps
  # TODO: How to actually prevent users from using the app without submitting a valid TOTP?

  defstruct name: :two_factor_totp,
            storage_field: nil,
            identity_field: nil,
            setup_action_name: nil,
            verify_action_name: nil,
            issuer: nil,
            resource: nil

  @type t :: %__MODULE__{
          name: :two_factor_totp,
          storage_field: atom,
          identity_field: atom,
          setup_action_name: atom,
          verify_action_name: atom,
          issuer: String.t(),
          resource: module
        }

  use AshAuthentication.Strategy.Custom, style: :add_on, entity: __MODULE__.Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: __MODULE__.Transformer
end
