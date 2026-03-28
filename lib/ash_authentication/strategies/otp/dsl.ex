# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, Otp}
  alias Spark.Dsl.Entity

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    %Entity{
      name: :otp,
      describe: "Strategy for authenticating using a one-time password sent to the user",
      args: [{:optional, :name, :otp}],
      hide: [:name],
      target: Otp,
      no_depend_modules: [:sender, :otp_generator],
      schema: [
        name: [
          type: :atom,
          doc: "Uniquely identifies the strategy.",
          required: true
        ],
        identity_field: [
          type: :atom,
          doc:
            "The name of the attribute which uniquely identifies the user, usually something like `username` or `email_address`.",
          default: :email
        ],
        otp_lifetime: [
          type:
            {:or,
             [
               :pos_integer,
               {:tuple, [:pos_integer, {:in, [:days, :hours, :minutes, :seconds]}]}
             ]},
          doc:
            "How long the OTP code is valid. If no unit is provided, then `minutes` is assumed.",
          default: {10, :minutes}
        ],
        otp_length: [
          type: :pos_integer,
          doc: "The length of the generated OTP code.",
          default: 6
        ],
        otp_characters: [
          type:
            {:in,
             [
               :unambiguous_uppercase,
               :unambiguous_alphanumeric,
               :digits_only,
               :uppercase_letters_only
             ]},
          doc: """
          The character set used to generate OTP codes:

          - `:unambiguous_uppercase` (default) — A–Z minus easily misread characters (I, L, O, S, Z)
          - `:unambiguous_alphanumeric` — unambiguous letters and digits combined
          - `:digits_only` — full 0–9
          - `:uppercase_letters_only` — full A–Z
          """,
          default: :unambiguous_uppercase
        ],
        otp_generator: [
          type: :atom,
          doc:
            "A module that implements `generate/1` and `normalize/1`. Defaults to `AshAuthentication.Strategy.Otp.DefaultGenerator`.",
          required: false
        ],
        registration_enabled?: [
          type: :boolean,
          doc:
            "Allows registering via OTP. Sign-in becomes an upsert action instead of a read action, so users who don't exist are created on first sign-in.",
          default: false
        ],
        case_sensitive?: [
          type: :boolean,
          doc:
            "Whether OTP codes are matched case-sensitively. When `false` (the default), codes are uppercased before comparison so `\"xkptmh\"` matches `\"XKPTMH\"`.",
          default: false
        ],
        single_use_token?: [
          type: :boolean,
          doc: "Automatically revoke the OTP token once it's been used for sign in.",
          default: true
        ],
        request_action_name: [
          type: :atom,
          doc: "The name to use for the request action. Defaults to `request_<strategy_name>`.",
          required: false
        ],
        sign_in_action_name: [
          type: :atom,
          doc:
            "The name to use for the sign in action. Defaults to `sign_in_with_<strategy_name>`.",
          required: false
        ],
        lookup_action_name: [
          type: :atom,
          doc:
            "The action to use when looking up a user by their identity. Defaults to `get_by_<identity_field>`."
        ],
        otp_param_name: [
          type: :atom,
          doc: "The name of the OTP parameter in the incoming sign-in request.",
          default: :otp,
          required: false
        ],
        sender: [
          type:
            {:spark_function_behaviour, AshAuthentication.Sender,
             {AshAuthentication.SenderFunction, 3}},
          doc: "How to send the OTP code to the user.",
          required: true
        ]
      ]
    }
  end
end
