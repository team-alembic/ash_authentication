<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Upgrading

## Upgrading to version 4.15.0

### Breaking Changes

#### 1. OAuth2 sign-in strategies must name the attribute that holds the email

A sign-in-only OAuth2 strategy attaches a new provider identity to the account its read action matched. Before this version it attached whenever `trust_email_verified?` was set and the provider sent `email_verified`. It never compared the email itself. An action filtered on a username therefore attached the sign-in to an account the signer-in did not own.

The rule now requires the provider's verified email to equal the account's own email. The new `email_field` option names the attribute that holds that email. It defaults to `:email`, and every strategy built on `oauth2` inherits it.

**This configuration no longer compiles:**

```elixir
attributes do
  uuid_primary_key :id
  attribute :username, :ci_string, allow_nil?: false, public?: true
end

authentication do
  strategies do
    github do
      # ...
      registration_enabled? false
    end
  end
end
```

```text
authentication -> strategies -> github -> email_field :
  `email_field` is set to `:email`, which is not an attribute of this resource.
```

Three things must be true together before the error appears:

1. The strategy trusts the provider's claim (`trust_email_verified? true`). The `apple`, `auth0`, `github`, `google` and `slack` strategies set this by default.
2. The strategy is sign-in only (`registration_enabled? false`).
3. `email_field` names no attribute of the resource.

A register strategy is never checked. It compares the verified email against the `upsert_identity` values that matched the account, so it needs no named attribute.

**Action required:** choose one of two resolutions.

- The resource holds the email under another name. Set `email_field` to that attribute:

  ```elixir
  github do
    email_field :email_address
    registration_enabled? false
  end
  ```

- The resource stores no email address. Set `trust_email_verified? false`:

  ```elixir
  github do
    trust_email_verified? false
    registration_enabled? false
  end
  ```

The configurations that now fail to compile are the ones that were silently attaching sign-ins to accounts the signer-in did not own. The compile error is the point of the change, not a cost of it.

An action filtered on the email is unaffected. Its matched value is the provider's email, so it attaches exactly as before.

**Also note:** a sign-in that no longer attaches has no linking path. `on_untrusted_email_match :confirm` is read by the register action only. The person must sign in with their existing method to link the provider.

Accounts already linked under the old rule stay linked. This change prevents new links. It does not unpick existing ones. Review your `UserIdentity` rows for links whose provider email does not match the linked account's email.

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
