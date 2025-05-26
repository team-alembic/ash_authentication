defmodule AshAuthentication.AddOn.TwoFactorTotp do
  @moduledoc """
  Support for two-factor authentication, using Time-Based One-Time Passwords (TOTP).
  """

  # TODO: Write all of the docs for the things
  #
  # TODO: How to actually prevent users from using the app without submitting a valid TOTP? Update
  # user's auth controller to not actually store the authentication result, but instead force a
  # TOTP request?
  #
  # TODO: How to make it opt-in on a per-level? eg. GitHub
  # Also, sudo mode (like GitHub. `phx.gen.auth` also does this)
  #
  # TODO: Recovery codes

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
