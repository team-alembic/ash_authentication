<!--
SPDX-FileCopyrightText: 2026 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Recovery Codes

Recovery codes are one-time backup codes that allow users to authenticate when
their primary two-factor method (e.g. TOTP authenticator app) is unavailable.
Each code can only be used once and is deleted after successful verification.

## Prerequisites

- AshAuthentication configured with a User resource
- A primary authentication strategy (e.g. password)
- Typically paired with TOTP for a complete 2FA setup

## Installation

<!-- tabs-open -->

### Using Igniter (recommended)

```sh
mix ash_authentication.add_strategy recovery_code
```

This creates a recovery code resource, adds the relationship and strategy to
your user resource, and generates a brute force preparation module.

### Manual Setup

Follow the steps below to set up recovery codes manually.

<!-- tabs-close -->

## Recovery Code Resource

Create a resource to store hashed recovery codes:

```elixir
# lib/my_app/accounts/recovery_code.ex
defmodule MyApp.Accounts.RecoveryCode do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    domain: MyApp.Accounts

  attributes do
    uuid_primary_key :id

    attribute :code, :string do
      allow_nil? false
      sensitive? true
      public? false
    end

    timestamps()
  end

  relationships do
    belongs_to :user, MyApp.Accounts.User, allow_nil?: false
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:code]
    end
  end

  postgres do
    table "recovery_codes"
    repo MyApp.Repo

    references do
      reference :user, on_delete: :delete
    end
  end
end
```

## Add Strategy to User Resource

Add a `has_many` relationship and the recovery code strategy:

```elixir
# lib/my_app/accounts/user.ex
defmodule MyApp.Accounts.User do
  # ...

  relationships do
    has_many :recovery_codes, MyApp.Accounts.RecoveryCode
  end

  authentication do
    strategies do
      recovery_code do
        recovery_code_resource MyApp.Accounts.RecoveryCode
        brute_force_strategy {:audit_log, :audit_log}
      end
    end
  end
end
```

With the default configuration, recovery codes are 12 characters from an
uppercase alphanumeric alphabet (A-Z, 0-9), hashed with SHA-256.

## Brute Force Protection

Recovery codes require a brute force protection strategy. The options are the
same as for TOTP:

**1. Audit Log (recommended)**

```elixir
brute_force_strategy {:audit_log, :audit_log}
```

Tracks failed verification attempts in the audit log and blocks requests that
exceed the configured failure threshold within a time window. This is the
default when using the Igniter installer, and requires an audit log add-on
(see the [Audit Log tutorial](/documentation/tutorials/audit-log.md)).

The window and threshold are configurable:

```elixir
recovery_code do
  recovery_code_resource MyApp.Accounts.RecoveryCode
  brute_force_strategy {:audit_log, :audit_log}
  audit_log_window {5, :minutes}
  audit_log_max_failures 5
end
```

**2. Rate Limiting (with AshRateLimiter)**

```elixir
brute_force_strategy :rate_limit
```

Requires the `AshRateLimiter` extension and rate limit configuration for the
verify action.

**3. Custom Preparation**

```elixir
brute_force_strategy {:preparation, MyApp.CustomBruteForcePreparation}
```

Create a preparation that implements your own protection logic. The preparation
must implement `supports/1` returning a list that includes `Ash.ActionInput`.

## Generated Actions

The strategy generates two actions on the user resource:

- **`verify_with_recovery_code`** — verifies a recovery code for a user. On
  success, deletes the used code and returns the user. On failure, returns nil.
- **`generate_recovery_code_codes`** — generates new recovery codes for a user.
  Deletes any existing codes and returns the plaintext codes in
  `user.__metadata__.recovery_codes`.

## Generating Codes

```elixir
strategy = AshAuthentication.Info.strategy!(MyApp.Accounts.User, :recovery_code)

{:ok, user} = AshAuthentication.Strategy.action(strategy, :generate, %{user: user}, [])

# The plaintext codes are in metadata (only available at generation time)
codes = user.__metadata__.recovery_codes
#=> ["AB3KMN7QR2XY", "CD5FGH8JT4WZ", ...]
```

Display these codes to the user and instruct them to save them securely. The
plaintext codes are only available at generation time — only hashed values are
stored in the database.

## Verifying Codes

```elixir
strategy = AshAuthentication.Info.strategy!(MyApp.Accounts.User, :recovery_code)

case AshAuthentication.Strategy.action(strategy, :verify, %{user: user, code: "AB3KMN7QR2XY"}, []) do
  {:ok, user} -> # Code valid, user authenticated
  {:error, _} -> # Code invalid or already used
end
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `recovery_code_resource` | — | The Ash resource that stores recovery codes. Required. |
| `hash_provider` | `SHA256Provider` | Hash provider for hashing codes. |
| `code_length` | `12` | Length of each generated code. |
| `code_alphabet` | `A-Z, 0-9` | Characters used when generating codes. |
| `recovery_code_count` | `10` | Number of codes to generate. |
| `code_field` | `:code` | Attribute on the recovery code resource that stores the hash. |
| `recovery_codes_relationship_name` | `:recovery_codes` | Name of the `has_many` relationship on the user. |
| `user_relationship_name` | `:user` | Name of the `belongs_to` relationship on the code resource. |
| `generate_enabled?` | `true` | Whether to generate the generate action. |
| `verify_action_name` | `:verify_with_<name>` | Name of the verify action. |
| `generate_action_name` | `:generate_<name>_codes` | Name of the generate action. |

## Using a Different Hash Provider

The default `AshAuthentication.SHA256Provider` requires codes with at least 60
bits of entropy. With the default 12-character alphabet of 36 characters, this
gives ~62 bits — comfortably above the minimum.

For shorter, more user-friendly codes, use a slow hash provider:

```elixir
recovery_code do
  recovery_code_resource MyApp.Accounts.RecoveryCode
  hash_provider AshAuthentication.BcryptProvider
  code_length 8
  brute_force_strategy {:preparation, MyApp.NoopBruteForcePreparation}
end
```

> ### Slow hashes have performance implications {: .info}
>
> Bcrypt and Argon2 are deliberately slow. Verifying a code requires checking
> against each stored hash individually, which may take up to ~1 second with 10
> codes. SHA-256 verification is near-instant because it uses atomic database
> lookups.

See [Recovery Code Security](../topics/recovery-code-security.md) for a detailed
explanation of the trade-offs.

## Security Considerations

1. **Brute force protection is mandatory** — every configuration must specify a strategy
2. **Codes are hashed at rest** — plaintext codes are only available at generation time
3. **Codes are single-use** — each code is deleted after successful verification
4. **Store codes securely** — instruct users to save codes in a password manager or printed copy
5. **Regenerating codes invalidates old ones** — generating new codes deletes all existing codes
6. **Pair with TOTP** — recovery codes are most useful as a backup for TOTP authentication
