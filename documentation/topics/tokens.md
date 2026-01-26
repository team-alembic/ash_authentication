<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Tokens

## Token Lifetime

Since refresh tokens are not yet included in `ash_authentication`, you should set the token lifetime to a reasonably long time to ensure a good user experience. Alternatively, refresh tokens can be implemented on your own.

## Requiring Token Storage

Using `d:AshAuthentication.Dsl.authentication.tokens.require_token_presence_for_authentication?` inverts the token validation behaviour from requiring that tokens are not revoked to requiring any token presented by a client to be present in the token resource to be considered valid.

Requires `store_all_tokens?` to be `true`.

`store_all_tokens?` instructs `AshAuthentication` to keep track of all tokens issued to any user. This is optional behaviour with `ash_authentication` in order to preserve as much performance as possible.

## Sign in Tokens

Enabled with `d:AshAuthentication.Strategy.Password.authentication.strategies.password.sign_in_tokens_enabled?`

Sign in tokens can be generated on request by setting the `:token_type` context to `:sign_in` when calling the sign in action. You might do this when you need to generate a short lived token to be exchanged for a real token using the `validate_sign_in_token` route. This is used, for example, by `ash_authentication_phoenix` (since 1.7) to support signing in a liveview, and then redirecting with a valid token to a controller action, allowing the liveview to show invalid username/password errors.

## Extra Claims

You can add custom claims to generated tokens using the `extra_claims` option. This is useful for including user-specific data like roles, permissions, or tenant information in your JWTs.

### DSL Configuration

Configure default extra claims that are included in all tokens for a resource:

```elixir
authentication do
  tokens do
    enabled? true
    token_resource MyApp.Token

    # Using a function (receives user and options)
    extra_claims fn user, _opts ->
      %{"role" => user.role, "tenant_id" => user.tenant_id}
    end

    # Or using a static map
    extra_claims %{"app_version" => "1.0"}
  end
end
```

The function receives the user record and options (containing tenant, etc.) and should return a map of claims to include in the token.

### Action-Level Claims

You can also add claims on a per-action basis using `AshAuthentication.add_token_claims/2`. This function works with changesets, queries, and action inputs.

For create actions (like registration):

```elixir
create :register_with_password do
  # ... other configuration
  change AshAuthentication.GenerateTokenChange
  change fn changeset, _ctx ->
    AshAuthentication.add_token_claims(changeset, %{"session_type" => "registration"})
  end
end
```

For read actions (like sign-in):

```elixir
MyApp.User
|> Ash.Query.for_read(:sign_in_with_password, %{email: email, password: password})
|> AshAuthentication.add_token_claims(%{"session_type" => "api"})
|> Ash.read_one!()
```

Action-level claims are merged with DSL-configured claims, with action-level claims taking precedence in case of conflicts.

### Accessing Extra Claims

When `store_all_tokens?` is enabled, extra claims are stored in the token resource's `extra_data` attribute. When a user authenticates via bearer token or session (with `require_token_presence_for_authentication?` enabled), the extra claims are restored and available in the user's metadata:

```elixir
# In a controller or plug
user = conn.assigns.current_user
claims = user.__metadata__.token_claims
# => %{"role" => "admin", "tenant_id" => "abc123"}
```

This allows you to access custom token data without needing to decode the JWT on every request.
