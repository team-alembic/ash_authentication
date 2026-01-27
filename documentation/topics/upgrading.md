<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Upgrading

## Upgrading to version 5.0.0

Version 5.0.0 includes several breaking changes related to action types and the Google OAuth strategy. Most changes can be handled automatically using the upgrade task.

### Dependencies

This version requires Assent ~> 0.3.0 (updated from ~> 0.2.9) and adds `nimble_totp` as a dependency for the new TOTP strategy. Run `mix deps.get` after updating your `ash_authentication` version.

### Automated Upgrade

If you have [Igniter](https://hexdocs.pm/igniter) installed, run:

```bash
mix ash_authentication.upgrade 4.x.x 5.0.0
```

Replace `4.x.x` with your current version. This will automatically:

- Convert token resource `revoked?` actions from `:read` to `:action` type
- Convert password reset and magic link request actions from `:read` to `:action` type
- Create `get_by_<identity_field>` read actions where needed
- Update `"google_hd"` references to `"hd"` in your codebase

### Breaking Changes

#### 1. Sender failures now propagate as errors

Previously, sender failures were silently ignored. Now, senders that return `{:error, reason}` will cause the authentication action to fail with an `AshAuthentication.Errors.SenderFailed` error.

**What this affects:**

- Password reset requests
- Magic link requests
- Confirmation emails

**Action required:** Review your sender implementations. If they can return `{:error, reason}`, ensure your application handles these failures appropriately. Senders returning `:ok` or `{:ok, result}` (common with mailer libraries) will continue to work unchanged.

**Recommended approach:** Consider using a durable background job library like [Oban](https://hexdocs.pm/oban) for sending authentication emails. This provides automatic retries, failure tracking, and prevents transient email delivery issues from blocking user authentication flows. Your sender can enqueue a job and return `:ok` immediately, while the actual email delivery happens asynchronously with built-in resilience.

```elixir
defmodule MyApp.AuthEmailSender do
  use AshAuthentication.Sender

  def send(user_or_email, token, opts) do
    %{user_or_email: user_or_email, token: token, opts: opts}
    |> MyApp.Workers.AuthEmail.new()
    |> Oban.insert()

    :ok
  end
end
```

#### 2. Request actions converted to generic actions

Password reset request (`request_password_reset_with_password`) and magic link request (`request_magic_link`) actions are now generated as `:action` type instead of `:read`.

**Action required:** If you have customised these actions as `:read` actions, the upgrader will convert them automatically. If you've made extensive customisations, review the converted code to ensure it still meets your requirements.

The new actions work with auto-generated `get_by_<identity_field>` read actions for user lookup.

#### 3. Token revoked action converted to generic action

The `revoked?` action on token resources is now a generic action returning a boolean, rather than a read action returning a record.

**Action required:** If you have a custom `revoked?` read action on your token resource, the upgrader will convert it automatically.

#### 4. Google strategy now uses OIDC

The Google OAuth strategy now uses OIDC (via Assent 0.3.0) instead of the legacy API. This changes two fields in the `user_info` map:

| Old | New |
|-----|-----|
| `user_info["google_hd"]` | `user_info["hd"]` |
| `user_info["email_verified"]` (string `"true"`) | `user_info["email_verified"]` (boolean `true`) |

**Action required:**

1. The upgrader will automatically rename `"google_hd"` to `"hd"` in your code
2. You must manually update any checks for `email_verified`:

```elixir
# Before
user_info["email_verified"] == "true"

# After
user_info["email_verified"] == true
```

### New Features

#### TOTP Two-Factor Authentication

Version 5.0.0 adds a complete TOTP (Time-based One-Time Password) strategy for two-factor authentication. See the [TOTP tutorial](/documentation/tutorials/totp.md) for setup instructions.

#### Extra JWT Claims

You can now add custom claims to JWT tokens using the `extra_claims` option in the tokens DSL section, or dynamically via `AshAuthentication.add_token_claims/2`. See the [tokens guide](/documentation/topics/tokens.md) for details.

### Other Improvements

- **Auto signout in AshAuthentication.Phoenix** - Automatic sign-out is now supported in the Phoenix integration
- **API key header prefix regex support** - The `ApiKey.Plug` now accepts regex patterns for header prefix matching
- **Better error handling** - `Jwt.token_for_user/2` now returns `{:error, AuthenticationFailed.t}` on failure instead of raising

## Upgrading to version 4.0.0

Version 4.0.0 of AshAuthentication adds support for Ash 3.0 and in line with [a number of changes in Ash](`e:ash:upgrading-to-3.0.html`) there are some corresponding changes to Ash Authentication:

- Token generation is enabled by default, meaning that you will have to explicitly set [`authentication.tokens.enabled?`](documentation/dsls/DSL-AshAuthentication.md#authentication-tokens-enabled?) to `false` if you don't need them.

- Sign in tokens are enabled by default in the password strategy. What this means is that instead of returning a regular user token on sign-in in the user's metadata, we generate a short-lived token which can be used to actually sign the user in. This is specifically to allow live-view based sign-in UIs to display an authentication error without requiring a page-load.

## Upgrading to version 3.6.0.

As of version 3.6.0 the `TokenResource` extension adds the `subject` attribute
which allows us to more easily match tokens to specific users. This unlocks
some new use-cases (eg sign out everywhere).

This means that you will need to generate new migrations and migrate your
database.

### Upgrade steps:

> ### Warning {: .warning}
>
> If you already have tokens stored in your database then the migration will
> likely throw a migration error due to the new `NOT NULL` constraint on
> `subject`. If this happens then you can either delete all your tokens or
> explicitly add the `subject` attribute to your resource with `allow_nil?` set
> to `true`. eg:
>
> ```elixir
> attributes do
>   attribute :subject, :string, allow_nil?: true
> end
> ```

1. Run `mix ash_postgres.generate_migrations --name=add_subject_to_token_resource`
2. Run `mix ash_postgres.migrate`
3. 🎉
