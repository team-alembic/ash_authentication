# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp do
  @moduledoc """
  Strategy for Time-based One-Time Password (TOTP) authentication.

  Provides TOTP support via [nimble_totp](https://hex.pm/packages/nimble_totp),
  allowing users to authenticate using time-based codes from authenticator apps
  like Google Authenticator, Authy, or 1Password.

  ## Requirements

  Your resource needs to meet the following minimum requirements:

  1. Have a primary key.
  2. An identity field (e.g., `email` or `username`) for identifying users.
  3. A sensitive binary field for storing the TOTP secret.
  4. A sensitive datetime field for tracking the last successful TOTP authentication.
  5. A brute force protection strategy (rate limiting, audit log, or custom preparation).

  ## Example

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false, public?: true
      attribute :totp_secret, :binary, sensitive?: true
      attribute :last_totp_at, :utc_datetime, sensitive?: true
    end

    authentication do
      tokens do
        enabled? true
        token_resource MyApp.Accounts.Token
      end

      strategies do
        totp do
          identity_field :email
          issuer "MyApp"
          brute_force_strategy {:audit_log, :my_audit_log}
        end
      end

      add_ons do
        audit_log :my_audit_log do
          audit_log_resource MyApp.Accounts.AuditLog
          log_actions [:sign_in_with_totp, :verify_with_totp, :confirm_setup_with_totp]
        end
      end
    end

    identities do
      identity :unique_email, [:email]
    end
  end
  ```

  ## Actions

  The TOTP strategy can generate up to four actions:

  - **setup** - Generates a new TOTP secret for the user. Returns the user with
    a `totp_url` calculation that can be rendered as a QR code.
  - **confirm_setup** - When `confirm_setup_enabled?` is true, this action verifies
    a TOTP code before activating the secret. Requires tokens to be enabled.
  - **sign_in** - Authenticates a user using their identity and a TOTP code.
  - **verify** - Checks if a TOTP code is valid for a given user (without signing in).

  ## Brute Force Protection

  TOTP codes have a small keyspace (typically 6 digits), making them vulnerable
  to brute force attacks. You must configure a `brute_force_strategy`:

  - `:rate_limit` - Uses `AshRateLimiter` to limit attempts.
  - `{:audit_log, :audit_log_name}` - Uses an audit log to track failed attempts.
  - `{:preparation, ModuleName}` - Custom preparation for rate limiting.

  ## Working with Actions

  You can interact with TOTP actions via the `AshAuthentication.Strategy` protocol:

      iex> strategy = AshAuthentication.Info.strategy!(MyApp.Accounts.User, :totp)
      ...> {:ok, user} = AshAuthentication.Strategy.action(strategy, :setup, %{user: existing_user})
      ...> user.totp_url_for_totp  # QR code URL

      iex> {:ok, true} = AshAuthentication.Strategy.action(strategy, :verify, %{user: user, code: "123456"})
  """

  defstruct __identifier__: nil,
            __spark_metadata__: nil,
            audit_log_max_failures: 5,
            audit_log_window: {5, :minutes},
            brute_force_strategy: nil,
            confirm_setup_enabled?: false,
            confirm_setup_action_name: nil,
            grace_period: nil,
            identity_field: nil,
            issuer: nil,
            last_totp_at_field: nil,
            name: :totp,
            period: 30,
            read_secret_from: nil,
            resource: nil,
            secret_field: nil,
            secret_length: 20,
            setup_enabled?: true,
            setup_action_name: nil,
            setup_token_lifetime: {10, :minutes},
            sign_in_enabled?: false,
            sign_in_action_name: nil,
            totp_url_field: nil,
            verify_enabled?: true,
            verify_action_name: nil

  use AshAuthentication.Strategy.Custom, entity: __MODULE__.Dsl.dsl()

  @type t :: %__MODULE__{
          __identifier__: any,
          __spark_metadata__: any,
          audit_log_max_failures: pos_integer,
          audit_log_window: pos_integer | {pos_integer, :days | :hours | :minutes | :seconds},
          brute_force_strategy: :rate_limit | {:audit_log, atom} | {:preparation, module},
          confirm_setup_enabled?: boolean,
          confirm_setup_action_name: atom,
          grace_period: non_neg_integer | nil,
          identity_field: atom,
          issuer: String.t(),
          last_totp_at_field: atom,
          name: atom,
          period: pos_integer,
          read_secret_from: atom | nil,
          resource: Ash.Resource.t(),
          secret_field: atom,
          secret_length: pos_integer,
          setup_enabled?: boolean,
          setup_action_name: atom,
          setup_token_lifetime: pos_integer | {pos_integer, :days | :hours | :minutes | :seconds},
          sign_in_enabled?: boolean,
          sign_in_action_name: atom,
          totp_url_field: atom,
          verify_enabled?: boolean,
          verify_action_name: atom
        }

  defdelegate transform(strategy, dsl), to: __MODULE__.Transformer
  defdelegate verify(strategy, dsl), to: __MODULE__.Verifier
end
