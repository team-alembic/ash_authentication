# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.Dsl do
  @moduledoc """
  Defines the Spark DSL entity for this strategy.
  """
  alias AshAuthentication.Strategy.Totp

  @doc false
  @spec dsl :: map
  def dsl do
    %Spark.Dsl.Entity{
      name: :totp,
      describe: """
      Adds TOTP-based one-time passcode authentication.
      """,
      args: [{:optional, :name, :totp}],
      target: Totp,
      identifier: :name,
      schema: [
        name: [
          type: :atom,
          doc: "Uniquely identifies the strategy.",
          required: true
        ],
        brute_force_strategy: [
          type:
            {:or,
             [
               {:literal, :rate_limit},
               {:tuple, [{:literal, :audit_log}, :atom]},
               {:tuple, [{:literal, :preparation}, {:behaviour, Ash.Resource.Preparation}]}
             ]},
          doc: "How you are mitigating brute-force token checks.",
          required: true
        ],
        identity_field: [
          type: :atom,
          doc:
            "The name of the attribute which uniquely identifies the user, usually something like `username` or `email_address`.",
          default: :username,
          required: false
        ],
        issuer: [
          type: :string,
          doc: "The TOTP issuer to use. Defaults to the strategy name.",
          required: false
        ],
        secret_field: [
          type: :atom,
          doc: "The name of the attribute within which to store the TOTP secret.",
          default: :totp_secret,
          required: false
        ],
        secret_length: [
          type: :pos_integer,
          doc:
            "The number of bytes to use when generating secrets. Default is 20 as per the [HOTP RFC](https://tools.ietf.org/html/rfc4226#section-4).",
          default: 20,
          required: false
        ],
        last_totp_at_field: [
          type: :atom,
          doc:
            "The name of the attribute or calculation used to track the last successful TOTP time.",
          default: :last_totp_at,
          required: false
        ],
        period: [
          type: :pos_integer,
          doc: "The period (in seconds) in which the code is valid.",
          default: 30,
          required: false
        ],
        setup_enabled?: [
          type: :boolean,
          doc:
            "If you do not want the setup action to be generated/validated you disable it by setting this to false.",
          required: false,
          default: true
        ],
        setup_action_name: [
          type: :atom,
          doc: "The name to use for the setup action. Defaults to `setup_with_<strategy_name>`.",
          required: false
        ],
        totp_url_field: [
          type: :atom,
          doc:
            "The name to use for the TOTP URL calculation. Defaults to `totp_url_for_<strategy_name>`.",
          required: false
        ],
        sign_in_enabled?: [
          type: :boolean,
          doc:
            "If you do not want users to be able to sign in using this strategy, set this to false.",
          required: false,
          default: false
        ],
        sign_in_action_name: [
          type: :atom,
          doc:
            "The name to use for the sign in action. Defaults to `sign_in_with_<strategy_name>`.",
          required: false
        ],
        verify_enabled?: [
          type: :boolean,
          doc:
            "If you do not want users to be able to verify their TOTP codes outside of the sign-in action (or you want to handle it yourself), set this to false.",
          required: false,
          default: true
        ],
        verify_action_name: [
          type: :atom,
          doc:
            "The name to use for the verify action. Defaults to `verify_with_<strategy_name>`.",
          required: false
        ],
        confirm_setup_enabled?: [
          type: :boolean,
          doc: """
          When enabled, the setup action will not store the secret directly on the user.
          Instead, it generates a setup token that must be confirmed with a valid TOTP code.
          This provides additional security by verifying the user has correctly saved their secret.
          """,
          required: false,
          default: false
        ],
        confirm_setup_action_name: [
          type: :atom,
          doc:
            "The name to use for the confirm setup action. Defaults to `confirm_setup_with_<strategy_name>`.",
          required: false
        ],
        setup_token_lifetime: [
          type:
            {:or,
             [
               :pos_integer,
               {:tuple, [:pos_integer, {:in, [:days, :hours, :minutes, :seconds]}]}
             ]},
          doc:
            "How long the setup token is valid. If no unit is provided, then `minutes` is assumed. Defaults to 10 minutes.",
          required: false,
          default: {10, :minutes}
        ],
        audit_log_window: [
          type:
            {:or,
             [
               :pos_integer,
               {:tuple, [:pos_integer, {:in, [:days, :hours, :minutes, :seconds]}]}
             ]},
          doc:
            "Time window for counting failed attempts when using the `{:audit_log, ...}` brute force strategy. If no unit is provided, then `minutes` is assumed. Defaults to 5 minutes.",
          required: false,
          default: {5, :minutes}
        ],
        audit_log_max_failures: [
          type: :pos_integer,
          doc:
            "Maximum allowed failures within the window before blocking when using the `{:audit_log, ...}` brute force strategy. Defaults to 5.",
          required: false,
          default: 5
        ]
      ]
    }
  end
end
