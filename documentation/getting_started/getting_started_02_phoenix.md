# Using with Phoenix

This guide assumes that you already have an Phoenix application set up with Ash.
If you don't then check out the [Phoenix topic on Ash
HQ](https://ash-hq.org/docs/guides/ash/2.2.0/topics/phoenix.md).

If you haven't already, read [Getting started with Ash
Authentication](getting_started_01_basic_setup.html). This provides a good
primer on creating the required resources to use Ash Authentication with your
Phoenix app.

## Add to your application's dependencies

Bring in the
[`ash_authentication_phoenix`](https://github.com/team-alembic/ash_authentication_phoenix)
dependency:

```elixir
# mix.exs

defp deps()
[
# ...
{:ash_authentication_phoenix, "~> x.x"}
]
end
```

Use `mix hex.info ash_authentication_phoenix` to quickly find the latest
version.

## [`AshAuthentication.Phoenix.Router`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Router.html)

`ash_authentication_phoenix` includes several helper macros which can generate
Phoenix routes for you. They are included by way of a `use` macro:

```elixir
# lib/my_app_web/router.ex

defmodule MyAppWeb.Router do
  use MyAppWeb, :router
  use AshAuthentication.Phoenix.Router

  pipeline :browser do
    # ...
    plug(:load_from_session)
  end

  pipeline :api do
    # ...
    plug(:load_from_bearer)
  end

  scope "/", MyAppWeb do
    pipe_through :browser
    sign_in_route
    sign_out_route AuthController
    auth_routes_for MyApp.Accounts.User, to: AuthController
  end
end
```

### [`sign_in_route/3`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Router.html#sign_in_route/3)

This helper generates a live route to the
[`AshAuthentication.Phoenix.SignInLive`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.SignInLive.html)
LiveView. This LiveView renders a generic sign-in/register screen. It is
entirely optional, and can be customised either by way of
[overrides](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Overrides.html)
or replaced entirely.

### [`sign_out_route/3`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Router.html#sign_out_route/3)

This helper generates a route which points to the `sign_out` action in your `AuthController`.

### [`auth_routes_for/2`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Router.html#auth_routes_for/2)

This helper generates all the required routes for all strategies supported by the provided resource.

### Generated routes

Given the above configuration you should see the following in your routes:

```
# mix phx.routes

auth_path  *    /auth/user/confirm                 MyAppWeb.AuthController {:user, :confirm, :confirm}
auth_path  *    /auth/user/password/register       MyAppWeb.AuthController {:user, :password, :register}
auth_path  *    /auth/user/password/sign_in        MyAppWeb.AuthController {:user, :password, :sign_in}
auth_path  *    /auth/user/password/reset_request  MyAppWeb.AuthController {:user, :password, :reset_request}
auth_path  *    /auth/user/password/reset          MyAppWeb.AuthController {:user, :password, :reset}
auth_path  *    /auth/user/auth0                   MyAppWeb.AuthController {:user, :auth0, :request}
auth_path  *    /auth/user/auth0/callback          MyAppWeb.AuthController {:user, :auth0, :callback}
auth_path  GET  /sign-in                           AshAuthentication.Phoenix.SignInLive :sign_in
auth_path  GET  /sign-out                          MyAppWeb.AuthController :sign_out
```

## [`AshAuthentication.Phoenix.Controller`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Controller.html)

Instead of using [`AshAuthentication.Plug`](AshAuthentication.Plug.html) as
suggested in [the previous guide](getting_started_01_basic_setup.md),
`ash_authentication_phoenix` comes with a generator which creates a
`Phoenix.Controller` by way of a `use` macro.

All functions in
[`AshAuthentication.Phoenix.Plug`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Plug.html)
are automatically imported.

You can define multiple versions if required (eg one for your `:api` pipeline
and another for your `:browser` pipeline). Let's define a version for a browser
client:

```elixir
# lib/my_app_web/controllers/auth_controller.ex

defmodule MyAppWeb.Controllers.AuthController do
  use MyAppWeb, :controller
  use AshAuthentication.Phoenix.Controller

  def success(conn, _activity, user, _token) do
    return_to = get_session(conn, :return_to) || Routes.path_path(conn, :index)

    conn
    |> delete_session(:return_to)
    |> store_in_session(user)
    |> assign(:current_user, user)
    |> redirect(to: return_to)
  end

  def failure(conn, _activity, _reason) do
    conn
    |> put_status(401)
    |> render("failure.html")
  end

  def sign_out(conn, _params) do
    return_to = get_session(conn, :return_to) || Routes.path_path(conn, :index)

    conn
    |> clear_session()
    |> redirect(to: return_to)
  end
end
```

### `success/4`

This callback is called when registration or sign-in is successful. You should
use it to prepare a response back to the user indicating that authentication was
successful.

It is called with the following arguments:

  * `conn` the Plug connection.
  * `activity` a tuple containing two atoms - the strategy name and the phase.
    You can use this if you need to provide different behaviour depending on the
    authentication method.
  * `user` the authenticated user record (ie an instance of your user resource).
  * `token` a string containing a JWT for this user, if tokens are enabled.
    Otherwise `nil`.

In the example above we set up the session to know who the user is on their next
request and redirect them to an appropriate location.

### `failure/3`

This callback is called when registration or sign-in is unsuccessful. You
should use this to render an error, or provide some other indication to the user
that authentication has failed.

It is called with the following arguments:

  * `conn` the Plug connection.
  * `activity` a tuple containing two atoms - the strategy name and the phase.
    You can use this if you need to provide different behaviour depending on the
    authentication method.
  * The reason for failure.  It _could_ be an `Ash.Error`, an `Ash.Changeset`,
    or any other failure.

In the example above we simply set the HTTP status to 401 and render an HTML page.

### `sign_out/2`

This is not strictly necessary, but if you have enabled the
[`sign_out_route/3`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Router.html#sign_out_route/3)
helper in your router, then this is the controller action which will be called.
Use this to perform any sign-out actions (like clearing the session or [revoking
a
token](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Plug.html#revoke_bearer_tokens/2))
and then sending the user on their way.

## Component library

`ash_authentication_phoenix` ships with a number of components allowing you to
pick the level of customisation you require.

  * [`AshAuthentication.Phoenix.Components.SignIn`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Components.SignIn.html)
    This is the top-level component, given a [resource
    configuration](t:AshAuthentication.resource_config) it will iterate through
    all the configured authentication providers and render their UI. You can
    place this directly into your sign-in page if you want.
  * [`AshAuthentication.Phoenix.Components.Password`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Components.Password.html)
    This component renders the UI for password authentication - both the
    registration and sign-in UI.
  * [`AshAuthentication.Phoenix.Components.Password.SignInForm`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Components.Password.SignInForm.html)
    This component renders the UI for a password authentication sign-in form.
  * [`AshAuthentication.Phoenix.Components.Password.RegisterForm`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Components.Password.RegisterForm.html)
    This component renders the UI for a password authentication registration
    form.
  * [`AshAuthentication.Phoenix.Components.Password.ResetForm`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Components.Password.ResetForm.html)
    This component renders the UI for a user to request a password reset.
  * [`AshAuthentication.Phoenix.Components.Password.Input`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Components.Password.Input.html)
    This module contains several function components which provide individual
    input fields and buttons for password authentication.
  * [`AshAuthentication.Phoenix.Components.OAuth2`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Components.OAuth2.html)
    A component which renders a sign-in button for an OAuth 2.0 provider.

## Overrides

All the components above and the
[`AshAuthentication.Phoenix.SignInLive`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.SignInLive.html)
LiveView are customisable via the
[`AshAuthentication.Phoenix.Overrides`](https://team-alembic.github.io/ash_authentication_phoenix/AshAuthentication.Phoenix.Overrides.html)
system.

Overrides allow you to configure CSS classes and other options for the
components without needing to modify them.

## Summary

In this guide we've learned how to add Ash Authentication to Phoenix, configure
routes and handle authentication.

Up next, [Using with
AshAdmin](getting_started_03_admin.html).
