<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Auto Sign-out

Auto sign-out automatically disconnects LiveView sessions when a user's tokens are revoked. This ensures that when a user signs out (or triggers "sign out everywhere"), any active LiveView sessions are immediately disconnected rather than remaining active until the next page refresh.

## When Auto Sign-out Triggers

Auto sign-out is triggered whenever tokens are revoked, which happens:

- When a user explicitly signs out
- When the `log_out_everywhere` add-on revokes all tokens for a user (e.g., after a password change)
- When tokens are manually revoked via `AshAuthentication.TokenResource.revoke/3`

## Prerequisites

1. **Tokens must be enabled** in your authentication configuration
2. **A TokenResource** must be configured
3. **AshAuthentication.Phoenix** must be installed (for the notifier and helpers)
4. The `log_out_everywhere` add-on is recommended for password change scenarios

## Configuration

### Step 1: Configure TokenResource (AshAuthentication)

Add the `endpoints` and `live_socket_id_template` options to your token resource:

```elixir
defmodule MyApp.Accounts.Token do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.TokenResource],
    domain: MyApp.Accounts

  postgres do
    table "tokens"
    repo MyApp.Repo
  end

  token do
    endpoints [MyAppWeb.Endpoint]
    live_socket_id_template fn %{jti: jti} -> "users_sessions:#{jti}" end
  end
end
```

- `endpoints` - List of Phoenix endpoints to notify when tokens are revoked
- `live_socket_id_template` - Function that generates the live socket ID from a map containing `%{jti: jti}`. Additional keys may be added in future versions.

### Step 2: Add the Notifier (AshAuthentication.Phoenix)

Add `AshAuthentication.Phoenix.TokenRevocationNotifier` to your token resource's notifiers:

```elixir
defmodule MyApp.Accounts.Token do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.TokenResource],
    domain: MyApp.Accounts,
    notifiers: [AshAuthentication.Phoenix.TokenRevocationNotifier]

  # ... rest of configuration
end
```

The notifier broadcasts disconnect messages through your configured endpoints when tokens are revoked.

### Step 3: Set Live Socket ID on Sign-in (AshAuthentication.Phoenix)

In your authentication controller, call `set_live_socket_id/2` after successful sign-in to store the socket ID in the session:

```elixir
defmodule MyAppWeb.AuthController do
  use MyAppWeb, :controller
  use AshAuthentication.Phoenix.Controller

  def success(conn, _activity, user, _token) do
    conn
    |> set_live_socket_id(user)
    |> store_in_session(user)
    |> assign(:current_user, user)
    |> redirect(to: ~p"/")
  end

  def failure(conn, _activity, _reason) do
    conn
    |> put_flash(:error, "Authentication failed")
    |> redirect(to: ~p"/sign-in")
  end

  def sign_out(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: ~p"/")
  end
end
```

## How It Works

1. When a user signs in, `set_live_socket_id/2` stores the live socket ID (generated from the token's JTI) in the session
2. LiveView uses this socket ID to identify the connection
3. When a token is revoked, the `TokenRevocationNotifier` uses the `live_socket_id_template` function to generate the same socket ID from the revoked token's JTI
4. The notifier broadcasts a disconnect message through the configured endpoints
5. LiveView receives the disconnect and terminates the session

## Complete Example

### Token Resource

```elixir
defmodule MyApp.Accounts.Token do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.TokenResource],
    domain: MyApp.Accounts,
    notifiers: [AshAuthentication.Phoenix.TokenRevocationNotifier]

  postgres do
    table "tokens"
    repo MyApp.Repo
  end

  token do
    endpoints [MyAppWeb.Endpoint]
    live_socket_id_template fn %{jti: jti} -> "users_sessions:#{jti}" end
  end
end
```

### User Resource with Log Out Everywhere

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  authentication do
    tokens do
      enabled? true
      token_resource MyApp.Accounts.Token
      store_all_tokens? true
    end

    strategies do
      password :password do
        identity_field :email
      end
    end

    add_ons do
      log_out_everywhere do
        apply_on_password_change? true
      end
    end
  end

  # ... attributes, identities, etc.
end
```

### Auth Controller

```elixir
defmodule MyAppWeb.AuthController do
  use MyAppWeb, :controller
  use AshAuthentication.Phoenix.Controller

  def success(conn, _activity, user, _token) do
    conn
    |> set_live_socket_id(user)
    |> store_in_session(user)
    |> assign(:current_user, user)
    |> redirect(to: ~p"/")
  end

  def failure(conn, _activity, _reason) do
    conn
    |> put_flash(:error, "Authentication failed")
    |> redirect(to: ~p"/sign-in")
  end

  def sign_out(conn, _params) do
    conn
    |> clear_session()
    |> redirect(to: ~p"/")
  end
end
```
