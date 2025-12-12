<!--
SPDX-FileCopyrightText: 2025 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# TOTP (Time-based One-Time Password) Tutorial

TOTP allows users to authenticate using time-based one-time passwords generated
by authenticator apps like Google Authenticator, Authy, or 1Password.

## Use Cases

TOTP can be used in two ways:

1. **Two-Factor Authentication (2FA)** - As a second factor after password authentication
2. **Standalone Authentication** - As the primary authentication method (passwordless)

This tutorial covers both approaches.

## Prerequisites

- AshAuthentication configured with a User resource
- A token resource if using `confirm_setup_enabled?` (recommended)

## Add Required Attributes

Add the following attributes to your User resource:

```elixir
# lib/my_app/accounts/user.ex
attributes do
  # ... existing attributes ...

  attribute :totp_secret, :binary do
    allow_nil? true
    sensitive? true
    public? false
  end

  attribute :last_totp_at, :utc_datetime do
    allow_nil? true
    public? false
  end
end
```

The `totp_secret` stores the shared secret, and `last_totp_at` prevents replay
attacks by tracking the last successful authentication time.

## Basic TOTP Setup (2FA Mode)

For 2FA, users set up TOTP after registering with another method (like password):

```elixir
# lib/my_app/accounts/user.ex
authentication do
  strategies do
    password :password do
      identity_field :email
    end

    totp do
      identity_field :email
      # Required: choose a brute force protection strategy
      brute_force_strategy {:preparation, MyApp.TotpBruteForcePreparation}
    end
  end
end
```

This generates:
- `setup_with_totp` action - generates a secret and stores it on the user
- `verify_with_totp` action - verifies a code without signing in
- `totp_url_for_totp` calculation - generates the `otpauth://` URL for QR codes

### Brute Force Protection

TOTP requires a brute force protection strategy. Options:

**1. Custom Preparation (simplest)**
```elixir
brute_force_strategy {:preparation, MyApp.TotpBruteForcePreparation}
```

Create a preparation that implements your protection logic:

```elixir
# lib/my_app/accounts/totp_brute_force_preparation.ex
defmodule MyApp.TotpBruteForcePreparation do
  use Ash.Resource.Preparation

  def prepare(query, _opts, _context) do
    # Implement rate limiting, account lockout, etc.
    # Return the query unchanged if allowed to proceed
    query
  end
end
```

**2. Rate Limiting (with AshRateLimiter)**
```elixir
brute_force_strategy :rate_limit
```

Requires the `AshRateLimiter` extension and rate limit configuration for TOTP actions.

**3. Audit Log**
```elixir
brute_force_strategy {:audit_log, :my_audit_log}
```

Requires an audit log add-on that logs TOTP actions.

## Two-Step Setup with Confirmation (Recommended)

For better security, use two-step setup. This ensures users have correctly saved
their secret before it's activated:

```elixir
authentication do
  tokens do
    enabled? true
    token_resource MyApp.Accounts.Token
  end

  strategies do
    totp do
      identity_field :email
      confirm_setup_enabled? true
      setup_token_lifetime {10, :minutes}
      brute_force_strategy {:preparation, MyApp.TotpBruteForcePreparation}
    end
  end
end
```

This changes the flow:

1. **Setup** - `setup_with_totp` returns a `setup_token` and `totp_url` in metadata
   (secret is NOT stored on user yet)
2. **Display QR Code** - Show the QR code to the user
3. **Confirm** - User enters a code, call `confirm_setup_with_totp` with the token and code
4. **Activation** - If code is valid, secret is stored on user

### Example Setup Flow

```elixir
# Step 1: Initiate setup
{:ok, user} = Ash.update(user, action: :setup_with_totp)
setup_token = user.__metadata__.setup_token
totp_url = user.__metadata__.totp_url

# Step 2: Display QR code (use totp_url with a QR code library)
# The URL format is: otpauth://totp/Issuer:user@example.com?secret=BASE32SECRET&issuer=Issuer

# Step 3: User scans QR code and enters the code from their app
{:ok, user} = Ash.update(user,
  action: :confirm_setup_with_totp,
  params: %{setup_token: setup_token, code: "123456"}
)

# User now has TOTP enabled
```

## Standalone TOTP Sign-In

To use TOTP as a primary authentication method:

```elixir
authentication do
  strategies do
    totp do
      identity_field :email
      sign_in_enabled? true
      brute_force_strategy {:preparation, MyApp.TotpBruteForcePreparation}
    end
  end
end
```

This generates a `sign_in_with_totp` action that takes an identity and code,
returning an authenticated user with a token.

## Verifying TOTP Codes

The `verify_with_totp` action checks if a code is valid without signing in.
This is useful for 2FA flows where you want to verify the code as a second step:

```elixir
# After password authentication, verify TOTP
strategy = AshAuthentication.Info.strategy!(MyApp.Accounts.User, :totp)
{:ok, true} = AshAuthentication.Strategy.action(strategy, :verify, %{
  user: user,
  code: "123456"
})
```

## Generating QR Codes

The `totp_url_for_totp` calculation generates the standard `otpauth://` URL:

```elixir
user = Ash.load!(user, :totp_url_for_totp)
qr_url = user.totp_url_for_totp
# => "otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp"
```

Use a QR code library to render this URL:

```elixir
# With eqrcode
qr_code = EQRCode.encode(qr_url)
svg = EQRCode.svg(qr_code)
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `identity_field` | `:username` | Field that identifies users (e.g., `:email`) |
| `secret_field` | `:totp_secret` | Attribute storing the TOTP secret |
| `last_totp_at_field` | `:last_totp_at` | Attribute tracking last successful auth |
| `issuer` | Strategy name | Displayed in authenticator apps |
| `period` | `30` | Code validity period in seconds (recommended: 15-300) |
| `secret_length` | `20` | Secret length in bytes (recommended: 16+, per RFC 4226) |
| `setup_enabled?` | `true` | Generate setup action |
| `sign_in_enabled?` | `false` | Generate sign-in action |
| `verify_enabled?` | `true` | Generate verify action |
| `confirm_setup_enabled?` | `false` | Use two-step setup flow (requires `setup_enabled?`) |
| `setup_token_lifetime` | `{10, :minutes}` | How long setup tokens are valid |

## Security Considerations

1. **Always use brute force protection** - TOTP codes are only 6 digits
2. **Use confirm_setup_enabled?** - Ensures users correctly saved their secret
3. **Store secrets securely** - Mark the secret field as `sensitive?: true`
4. **Track last_totp_at** - Prevents replay attacks within the same time window
5. **Provide backup codes** - Consider implementing backup codes for account recovery
