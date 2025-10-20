<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Audit Log Tutorial

The audit log add-on provides automatic logging of authentication events (sign in, registration, failures, etc.) to help you track security-relevant activities in your application.

## Installation

<!-- tabs-open -->

### With Igniter (recommended)

Use `mix ash_authentication.add_add_on audit_log` to automatically set up audit logging:

```bash
mix ash_authentication.add_add_on audit_log
```

This will:
- Create the audit log resource
- Add the add-on to your user resource
- Ensure the AshAuthentication.Supervisor is in your application supervision tree
- Generate and run migrations

You can customise the installation with options:

```bash
# Custom audit log resource name
mix ash_authentication.add_add_on audit_log --audit-log MyApp.Accounts.AuthAuditLog

# Include sensitive fields
mix ash_authentication.add_add_on audit_log --include-fields email,username

# Exclude specific strategies
mix ash_authentication.add_add_on audit_log --exclude-strategies magic_link,oauth

# Exclude specific actions
mix ash_authentication.add_add_on audit_log --exclude-actions sign_in_with_token
```

### Manually

If you prefer to set up audit logging manually, continue with the steps below:

#### Create the audit log resource

First, create a resource to store the audit logs. This resource uses the `AshAuthentication.AuditLogResource` extension which handles all the necessary setup:

```elixir
defmodule MyApp.Accounts.AuditLog do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.AuditLogResource],
    domain: MyApp.Accounts

  postgres do
    table "account_audit_logs"
    repo MyApp.Repo
  end
end
```

The extension automatically creates all required attributes and actions. You don't need to define any manually unless you want to customise them.

#### Add the audit log add-on to your user resource

Next, add the audit log add-on to your user resource's authentication configuration:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  attributes do
    uuid_primary_key :id
    attribute :email, :ci_string, allow_nil?: false, public?: true, sensitive?: true
    attribute :hashed_password, :string, allow_nil?: false, sensitive?: true
  end

  authentication do
    tokens do
      enabled? true
      token_resource MyApp.Accounts.Token
    end

    add_ons do
      audit_log do
        audit_log_resource MyApp.Accounts.AuditLog
      end
    end

    strategies do
      password :password do
        identity_field :email
      end
    end
  end

  identities do
    identity :unique_email, [:email]
  end
end
```

#### Generate and run migrations

Generate migrations for the audit log table:

```bash
mix ash.codegen create_accounts_audit_logs
mix ash.migrate
```

#### Start the audit log batcher

The audit log uses batched writes to reduce database load. Add the `AshAuthentication.Supervisor` to your application's supervision tree:

```elixir
# lib/my_app/application.ex
defmodule MyApp.Application do
  use Application

  def start(_type, _args) do
    children = [
      MyApp.Repo,
      # Add this line
      {AshAuthentication.Supervisor, otp_app: :my_app}
    ]

    opts = [strategy: :one_for_one, name: MyApp.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
```

That's it! Authentication events will now be logged automatically.


<!-- tabs-close -->

## What gets logged?

The audit log automatically tracks:
- Successful and failed authentication attempts
- User registration events
- The authentication strategy used (password, OAuth2, magic link, etc.)
- The action name that triggered the event
- User subject (when available)
- Timestamp of the event
- Non-sensitive parameters from the request
- Sensitive parameters that are explicitly configured

## Viewing audit logs

You can read audit logs like any other Ash resource:

```elixir
# Get all audit logs
MyApp.Accounts.AuditLog
|> Ash.read!()

# Filter by user
MyApp.Accounts.AuditLog
|> Ash.Query.filter(subject == ^user_subject)
|> Ash.read!()

# Filter by action
MyApp.Accounts.AuditLog
|> Ash.Query.filter(action_name == :sign_in_with_password)
|> Ash.read!()

# Filter by status
MyApp.Accounts.AuditLog
|> Ash.Query.filter(status == :failure)
|> Ash.read!()
```

## Configuration options

### Include sensitive fields

By default, sensitive arguments and attributes (marked with `sensitive?: true`) are filtered out of the audit logs. You can explicitly include specific fields:

```elixir
authentication do
  add_ons do
    audit_log do
      audit_log_resource MyApp.Accounts.AuditLog
      include_fields [:email, :username]
    end
  end
end
```

### Exclude specific strategies

If you want to exclude certain authentication strategies from being logged:

```elixir
authentication do
  add_ons do
    audit_log do
      audit_log_resource MyApp.Accounts.AuditLog
      exclude_strategies [:magic_link]
    end
  end
end
```

### Exclude specific actions

To exclude specific actions from being logged:

```elixir
authentication do
  add_ons do
    audit_log do
      audit_log_resource MyApp.Accounts.AuditLog
      exclude_actions [:sign_in_with_token]
    end
  end
end
```

### Customise log retention

By default, audit logs are retained for 90 days. You can change this or disable automatic cleanup:

```elixir
defmodule MyApp.Accounts.AuditLog do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.AuditLogResource],
    domain: MyApp.Accounts

  audit_log do
    # Keep logs for 30 days
    log_lifetime 30

    # Or disable automatic cleanup
    # log_lifetime :infinity
  end

  postgres do
    table "account_audit_log"
    repo MyApp.Repo
  end
end
```

### Configure write batching

The audit log batches writes to reduce database load. You can customise this behaviour:

```elixir
defmodule MyApp.Accounts.AuditLog do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.AuditLogResource],
    domain: MyApp.Accounts

  audit_log do
    write_batching do
      enabled? true
      # Write batch every 5 seconds
      timeout :timer.seconds(5)
      # Or when batch reaches 50 records
      max_size 50
    end
  end

  postgres do
    table "account_audit_log"
    repo MyApp.Repo
  end
end
```

To disable batching entirely (writes happen immediately):

```elixir
audit_log do
  write_batching do
    enabled? false
  end
end
```

### Configure IP address privacy

To comply with privacy regulations like GDPR, you can control how IP addresses are stored in audit logs:

```elixir
authentication do
  add_ons do
    audit_log do
      audit_log_resource MyApp.Accounts.AuditLog

      # IP privacy options: :none | :hash | :truncate | :exclude
      ip_privacy_mode :truncate

      # Network masks for truncation (optional, these are the defaults)
      ipv4_truncation_mask 24  # Keep first 3 octets
      ipv6_truncation_mask 48  # Keep first 3 segments
    end
  end
end
```

Available IP privacy modes:

- `:none` (default) - Store IP addresses as-is without modification
- `:hash` - Hash IP addresses using SHA256 with application secret as salt
- `:truncate` - Truncate IP addresses to a network prefix (e.g., 192.168.1.100 → 192.168.1.0/24)
- `:exclude` - Don't store IP addresses at all

When using `:truncate` mode, the default masks are:
- IPv4: `/24` - Keeps first 3 octets (e.g., 192.168.1.0/24)
- IPv6: `/48` - Keeps first 3 segments (e.g., 2001:db8:85a3::/48)

Example configurations:

```elixir
# Hash all IP addresses for privacy
audit_log do
  audit_log_resource MyApp.Accounts.AuditLog
  ip_privacy_mode :hash
end

# Truncate with more aggressive masking
audit_log do
  audit_log_resource MyApp.Accounts.AuditLog
  ip_privacy_mode :truncate
  ipv4_truncation_mask 16  # Keep first 2 octets (more privacy)
  ipv6_truncation_mask 32  # Keep first 2 segments (more privacy)
end

# Exclude IP addresses entirely
audit_log do
  audit_log_resource MyApp.Accounts.AuditLog
  ip_privacy_mode :exclude
end
```

The IP privacy transformation applies to all IP-related fields in the request metadata:
- `remote_ip` - The direct client IP
- `x_forwarded_for` - Proxy chain IPs
- `forwarded` - Standard forwarded header with IP information

## Audit log attributes

Each audit log entry contains:

- `id` - Unique identifier for the log entry
- `subject` - The authenticated user's subject string (if available)
- `strategy` - The authentication strategy used (`:password`, `:github`, etc.)
- `audit_log` - The name of the audit log add-on instance
- `logged_at` - When the event occurred
- `action_name` - The action that triggered the event
- `status` - `:success`, `:failure`, or `:unknown`
- `extra_data` - Additional information including:
  - `actor` - The actor performing the action (if any)
  - `tenant` - The tenant context (if using multi-tenancy)
  - `request` - Request metadata
  - `params` - Non-sensitive parameters from the action
- `resource` - The resource module that was authenticated

## Security considerations

- Sensitive fields (passwords, tokens, API keys) are automatically filtered from audit logs unless explicitly included via `include_fields`
- IP addresses can be hashed, truncated, or excluded for privacy compliance using the `ip_privacy_mode` option
- Audit logs should be stored in a resilient data layer like PostgreSQL
- Consider setting up alerts for suspicious patterns (multiple failed logins, etc.)
- Ensure proper access controls on the audit log resource using Ash policies
- The audit log resource doesn't have default policies - you should add them based on your security requirements

## Example: Adding policies to audit logs

```elixir
defmodule MyApp.Accounts.AuditLog do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.AuditLogResource],
    domain: MyApp.Accounts,
    authorizers: [Ash.Policy.Authorizer]

  policies do
    # Only admins can read audit logs
    policy action_type(:read) do
      authorize_if relates_to_actor_via([:user, :admin])
    end

    # Allow AshAuthentication to write logs
    policy action_type(:create) do
      authorize_if AshAuthentication.Checks.AshAuthenticationInteraction
    end
  end

  postgres do
    table "account_audit_log"
    repo MyApp.Repo
  end
end
```
