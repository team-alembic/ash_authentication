# Integrating Ash Authentication and Phoenix

This guide assumes that you already have an Phoenix application set up with Ash.
If you don't then check out the [Phoenix topic on Ash
HQ](https://ash-hq.org/docs/guides/ash/2.2.0/topics/phoenix.md).

If you haven't already, read {{link:ash_authentication:guide:getting_started_01_basic_setup|Getting started with Ash Authentication}}. This provides a good
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
    ____mix_dep_ash_authentication_phoenix____
]
end
```

Use `mix hex.info ash_authentication_phoenix` to quickly find the latest
version.

## {{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.Router}}

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

### {{link:ash_authentication_phoenix:function:AshAuthentication.Phoenix.Router.sign_in_route/3|`sign_in_route/3`}}

This helper generates a live route to the `{{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.SignInLive}}`
LiveView. This LiveView renders a generic sign-in/register screen. It is
entirely optional, and can be customised either by way of {{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.Overrides|overrides}}
or replaced entirely.

### {{link:ash_authentication_phoenix:function:AshAuthentication.Phoenix.Router.sign_out_route/3|`sign_out_route/3`}}

This helper generates a route which points to the `sign_out` action in your `AuthController`.

### {{link:ash_authentication_phoenix:function:AshAuthentication.Phoenix.Router.auth_routes_for/2|`auth_routes_for/2`}}

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

## `{{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.Controller}}`

Instead of using `AshAuthentication.Plug` as
suggested in {{link:ash_authentication:guide:getting_started_01_basic_setup|the previous guide}},
`ash_authentication_phoenix` comes with a generator which creates a
`Phoenix.Controller` by way of a `use` macro.

All functions in {{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.Plug}}
are automatically imported.

You can define multiple versions if required (eg one for your `:api` pipeline
and another for your `:browser` pipeline). Let's define a version for a browser
client:

> Remember to define an appropriate template in `failure.html.heex` for your
> controller.

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
{{link:ash_authentication_phoenix:function:AshAuthentication.Phoenix.Router.sign_out_route/3|`sign_out_route/3`}}
helper in your router, then this is the controller action which will be called.
Use this to perform any sign-out actions (like clearing the session or {{link:ash_authentication_phoenix:function:AshAuthentication.Phoenix.Plug.revoke_bearer_tokens/2|revoking a token}}
and then sending the user on their way.

## Component library

`ash_authentication_phoenix` ships with a number of components allowing you to
pick the level of customisation you require.

  * {{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.Components.SignIn}}
    This is the top-level component, given a [resource
    configuration](t:AshAuthentication.resource_config) it will iterate through
    all the configured authentication providers and render their UI. You can
    place this directly into your sign-in page if you want.
  * {{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.Components.Password}}
    This component renders the UI for password authentication - both the
    registration and sign-in UI.
  * {{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.Components.Password.SignInForm}}
    This component renders the UI for a password authentication sign-in form.
  * {{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.Components.Password.RegisterForm}}
    This component renders the UI for a password authentication registration
    form.
  * {{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.Components.Password.ResetForm}}
    This component renders the UI for a user to request a password reset.
  * {{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.Components.Password.Input}}
    This module contains several function components which provide individual
    input fields and buttons for password authentication.
  * {{link:ash_authentication_phoenix:module:AshAuthentication.Phoenix.Components.OAuth2}}
    A component which renders a sign-in button for an OAuth 2.0 provider.

### Overrides

All the components above and the {{link:ash_authentication_phoenix:AshAuthentication.Phoenix.SignInLive}}
LiveView are customisable via the {{link:ash_authentication_phoenix:AshAuthentication.Phoenix.Overrides}}
system.

Overrides allow you to configure CSS classes and other options for the
components without needing to modify them.

### Tailwind

If you plan on using our default [Tailwind](https://tailwindcss.com/)-based
components without overriding them you will need to modify your
`assets/tailwind.config.js` to include the `ash_authentication_phoenix`
dependency:

```javascript
module.exports = {
  content: [
    // Other paths.
    "../deps/ash_authentication_phoenix/**/*.ex"
  ]
}
```

## Summary

In this guide we've learned how to add Ash Authentication to Phoenix, configure
routes and handle authentication.
