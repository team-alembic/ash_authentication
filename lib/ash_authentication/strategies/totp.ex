# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp do
  @moduledoc """
  TOTP support for authenticating users.

  Provides TOTP via the [nimble_totp](https://hex.pm/packages/nimble_totp) allowing users to authenticate with a one-time code.
  """

  defstruct __spark_metadata__: nil,
            brute_force_strategy: nil,
            identity_field: nil,
            issuer: nil,
            last_totp_at_field: nil,
            name: :totp,
            period: 30,
            resource: nil,
            secret_field: nil,
            secret_length: 20,
            setup_action_name: nil,
            verify_action_name: nil

  use AshAuthentication.Strategy.Custom, entity: __MODULE__.Dsl.dsl()

  @type t :: %__MODULE__{
          __spark_metadata__: nil,
          brute_force_strategy: :rate_limit | {:audit_log, atom} | {:preparation, module},
          identity_field: atom,
          issuer: String.t(),
          last_totp_at_field: atom,
          name: atom,
          period: pos_integer,
          resource: Ash.Resource.t(),
          secret_field: atom,
          secret_length: pos_integer,
          setup_action_name: atom,
          verify_action_name: atom
        }

  defdelegate transform(strategy, dsl), to: __MODULE__.Transformer
  defdelegate verify(strategy, dsl), to: __MODULE__.Verifier
end
