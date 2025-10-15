<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Remember Me Authentication Tutorial

The Remember Me strategy allows authenticating users with long lived tokens
that are typically stored in a browser's cookies and that exist beyond a single session. 

The Remember Me strategy is versatile with a lot of escape hatches to integrate it 
with other strategies in variety of use cases. The most common use case is to add 
a "Remember me" checkbox to your password form, giving your users a way to remain 
signed in for long periods of time. This tutorial will focus on that use case.

Remember Me does not require Phoenix or AshAuthenticationPhoenix, but we'll assume
you're using both for this tutorial. We'll also assume that your authenticated
resource is User.

## Add the Remember Me strategy to your User resource.

```elixir
# lib/my_app/accounts/user.ex
authentication do
  ...
  # If you don't already have tokens enabled, add them. Tokens are required.
  tokens do
    enabled? true
    store_all_tokens? true
    require_token_presence_for_authentication? true
  end

  addons do
    ...
    # Recommended: use the logout everywhere add on to revoke
    # Remember Me tokens on password change.
    log_out_everywhere do
      apply_on_password_change? true
    end
  end

  strategies do
    ...
    # Add the remember me strategy
    remember_me do # Optionally name the strategy: `remember_me :remember_me do`
      sign_in_action_name :sign_in_with_remember_me. # Optional defaults to :sign_in_with_[:strategy_name]
      cookie_name :remember_me # Optional. Defaults to :remember_me
      token_lifetime {30, :days} # Optional. Defaults to {30, :days}
    end
  end
end
```

## Optionally add the Remember Me sign in action

This action will be called by sign_in_with_remember_me plug to validate the remember me 
token, and generate a token for the session.

```elixir
# lib/my_app/accounts/user.ex
actions do
  ...

  # If not provided, a :sign_in_with_remember_me action will be 
  # automagically created for you.
  read :sign_in_with_remember_me do
    description "Attempt to sign in using a remember me token."
    get? true

    argument :token, :string do
      description "The remember me token."
      allow_nil? false
      sensitive? true
    end

    # validates the provided sign in token and generates a token
    prepare AshAuthentication.Strategy.RememberMe.SignInPreparation

    metadata :token, :string do
      description "A JWT that can be used to authenticate the user."
      allow_nil? false
    end
  end
end
```

## Update your existing sign in actions to generate Remember Me tokens

For each sign in action that might generate a Remember Me token, add an argument, 
preparation, and metadata. We're going to add it to two actions: :sign_in_with_password 
and :sign_in_with_token which is used by by AshAuthenticationPhoenix's liveview 
password form.

```elixir
# lib/my_app/accounts/user.ex
actions do
  read :sign_in_with_password do
    description "Attempt to sign in using a email and password."
    get? true

    argument :email, :ci_string do
      description "The email to use for retrieving the user."
      allow_nil? false
    end

    argument :password, :string do
      description "The password to check for the matching user."
      allow_nil? false
      sensitive? true
    end

    # 1 of 3: Add the argument
    argument :remember_me, :boolean do  # Optionally, use your own argument name
      description "Whether to generate a remember me token."
      allow_nil? true
    end

    prepare AshAuthentication.Strategy.Password.SignInPreparation

    # 2 of 3: Add the preparation. Optionally include the strategy_name 
    # and argument if not using the defaults.
    # prepare {AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation, strategy_name: :remember_me, argument: :remember_me}
    prepare AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation

    metadata :token, :string do
      description "A JWT that can be used to authenticate the user."
      allow_nil? false
    end

    # 3 of 3: Add the metadata attribute
    metadata :remember_me, :map do
      description "A map with the remember me token and strategy."
      allow_nil? true
    end
  end

  read :sign_in_with_token do
    description "Attempt to sign in using a short-lived sign in token."
    get? true

    argument :token, :string do
      description "The short-lived sign in token."
      allow_nil? false
      sensitive? true
    end

    # 1 of 3: Add the argument
    argument :remember_me, :boolean do
      description "Whether to generate a remember me token."
      allow_nil? true
    end

    prepare AshAuthentication.Strategy.Password.SignInWithTokenPreparation

    # 2 of 3: Add the preparation
    # prepare {AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation, strategy_name: :remember_me, argument: :remember_me}
    prepare AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation

    metadata :token, :string do
      description "A JWT that can be used to authenticate the user."
      allow_nil? false
    end

    # 3 of 3: Add the metadata
    metadata :remember_me, :map do
      description "A map with the remember me token and strategy."
      allow_nil? true
    end
  end
end
```

## Update your AuthController

### Using AshAuthentication.Phoenix

Implement the `put_remember_me_cookie/3` callback with your desired cookie options

```elixir
# lib/my_app_web/controllers/auth_controller.ex
defmodule MyAppWeb.AuthController do
  use MyAppWeb, :controller
  use AshAuthentication.Phoenix.Controller

  # The `clear_session/2` provided by AshAuthentication.Phoenix  will call 
  # `delete_all_remember_me_cookies/2` for you.
  def sign_out(conn, _params) do
    return_to = get_session(conn, :return_to) || ~p"/"

    conn
    |> clear_session(:my_otp_app)
    |> put_flash(:info, "You are now signed out")
    |> redirect(to: return_to)
  end
  ...

  # define put_rememeber_me callback to set your cookie options
  @remember_me_cookie_options [
    # cookie is only readable by HTTP/S
    http_only: true,
    # only send the cookie over HTTPS, except in development
    # otherwise Safari will block the cookie
    secure: Mix.env() != :dev,
    # prevents the cookie from being sent with cross-site requests
    same_site: "Lax"
  ]

  @impl AshAuthentication.Phoenix.Controller
  def put_remember_me_cookie(conn, cookie_name, %{token: token, max_age: max_age}) do
    cookie_options = Keyword.put(@remember_me_cookie_options, :max_age, max_age)

    conn
    |> put_resp_cookie(cookie_name, token, cookie_options)
  end
end
```

### Without AshAuthenticationPhoenix

On successful sign in, set the cookie with:
```elixir
AshAuthentication.Strategy.RememberMe.Plug.Helpers.maybe_put_remember_me_cookies(conn, auth_result)
```

On sign out, remove all remember me cookies with:
```elixir
AshAuthentication.Strategy.RememberMe.Plug.Helpers.delete_all_remember_me_cookies(conn, :my_otp_app)
```


## Update your router

Add the plug to sign in using the cookie. This plug will call the 
sign_in_with_remember_me action define above.

```elixir
# lib/my_app_web/router.ex
defmodule MyAppWeb.Router do
  use MyAppWebWeb, :router
  use AshAuthentication.Phoenix.Router

  ...
  pipeline :browser do
    ...
    # Add the sign_in_with_remember_me plug *before* load_from_session
    # It will come from either `use AshAuthentication.Plug` or `use AshAuthentication.Phoenix.Router`
    plug :sign_in_with_remember_me
    plug :load_from_session
  end
  ...
end
```

And that's it! AshAuthenicationPhoenix should now display a Remember Me checkbox
in the password authentication form.