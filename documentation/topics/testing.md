<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Testing

Tips and tricks to help test your apps.

## When using the Password strategy

AshAuthentication uses `bcrypt_elixir` for hashing passwords for secure storage, which by design has a high computational cost. To reduce the cost (make hashing faster), you can reduce the number of computation rounds it performs in tests:

```elixir
# in config/test.exs

# Do NOT set this value for production
config :bcrypt_elixir, log_rounds: 1
```

## Testing authenticated LiveViews

In order to test authenticated LiveViews, you will need to seed a test user and
log in it.  While you may certainly use a helper that logs in through the UI
each time, it's a little more efficient to call the sign-in code directly.

This can be done by adding a helper function in `MyAppWeb.ConnCase` found in
`test/support/conn_case.ex`.  In this example it's called
`register_and_log_in_user`.

```elixir
defmodule MyAppWeb.ConnCase do
  use ExUnit.CaseTemplate

  using do
    # ...
  end

  def register_and_log_in_user(%{conn: conn} = context) do
    email = "user@example.com"
    password = "password"
    {:ok, hashed_password} = AshAuthentication.BcryptProvider.hash(password)

    Ash.Seed.seed!(MyApp.Accounts.User, %{
      email: email,
      hashed_password: hashed_password
    })

    # Replace `:password` with the appropriate strategy for your application.
    strategy = AshAuthentication.Info.strategy!(MyApp.Accounts.User, :password)

    {:ok, user} =
      AshAuthentication.Strategy.action(strategy, :sign_in, %{
        email: email,
        password: password
      })

    new_conn =
      conn
      |> Phoenix.ConnTest.init_test_session(%{})
      |> AshAuthentication.Plug.Helpers.store_in_session(user)

   %{context | conn: new_conn}
  end
end
```

Now in your LiveView tests you can pass this function to `setup`:

```elixir
defmodule MyAppWeb.MyLiveTest do
  use MyAppWeb.ConnCase

  setup :register_and_log_in_user

  test "some test", %{conn: conn} do
    {:ok, lv, _html} = live(conn, ~p"/authenticated-route")

    # ...
  end
end
```

If required, it can also be called directly inside a `test` block:

```elixir
test "some test", context do
  %{conn: conn} = register_and_log_in_user(context)

  {:ok, lv, _html} = live(conn, ~p"/authenticated-route")

  # ...
end
```
