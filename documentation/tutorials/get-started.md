<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Get started with Ash Authentication

If you haven't already, read [the getting started guide for
Ash](https://hexdocs.pm/ash/get-started.html). This
assumes that you already have resources set up, and only gives you the steps to
add authentication to your resources and APIs.

<!-- tabs-open -->

### Using Igniter (recommended)

#### Install the extension

```sh
mix igniter.install ash_authentication --auth-strategy magic_link,password
```

##### Using Phoenix?

Use the following. If you have not yet run the above command, this will prompt you to do so,
so you can run both or only this one.

```sh
mix igniter.install ash_authentication_phoenix --auth-strategy magic_link,password
```

### Manual

#### Add to your application's dependencies

Bring in the `ash_authentication` dependency:

```elixir
# mix.exs

defp deps()
  [
    # ...
    {:ash_authentication, "~> 4.0"}
  ]
end
```

And add `ash_authentication` to your `.formatter.exs`:

```elixir
# .formatter.exs
[
  import_deps: [..., :ash_authentication]
]
```

#### Create authentication domain and resources

Let's create an `Accounts` domain in our application which provides a `User`
resource and a `Token` resource. This tutorial is assuming that you are using `AshPostgres`.

First, let's define our domain:

```elixir
# lib/my_app/accounts.ex

defmodule MyApp.Accounts do
  use Ash.Domain

  resources do
    resource MyApp.Accounts.User
    resource MyApp.Accounts.Token
  end
end
```

Be sure to add it to the `ash_domains` config in your `config.exs`

```elixir
# in config/config.exs
config :my_app, ash_domains: [..., MyApp.Accounts]
```

Next, let's define our `Token` resource. This resource is needed
if token generation is enabled for any resources in your application. Most of
the contents are auto-generated, so we just need to provide the data layer
configuration and the API to use.

But before we do, we need to install a postgres extension.

```elixir
# lib/my_app/repo.ex

defmodule MyApp.Repo do
  use AshPostgres.Repo, otp_app: :my_app

  def installed_extensions do
    ["ash-functions", "citext"]
  end
end
```

#### Setup Token Resource

```elixir
# lib/my_app/accounts/token.ex
defmodule MyApp.Accounts.Token do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.TokenResource],
    # If using policies, enable the policy authorizer:
    authorizers: [Ash.Policy.Authorizer],
    domain: MyApp.Accounts

  postgres do
    table "tokens"
    repo MyApp.Repo
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end
  end
end
```

#### Supervisor

AshAuthentication includes a supervisor which you should add to your
application's supervisor tree. This is used to run any periodic jobs related to
your authenticated resources (removing expired tokens, for example).

##### Example

```elixir
defmodule MyApp.Application do
  use Application

  def start(_type, _args) do
    children = [
      # ...
      # add this line -->
      {AshAuthentication.Supervisor, otp_app: :my_app}
      # <-- add this line
    ]
    # ...
  end
end
```

Lastly let's define our `User` resource. Note that we aren't defining any authentication strategies here.
This setup is used for all strategies. Once you have done this, you can follow one of the strategy specific
guides at the bottom of this page.

```elixir
# lib/my_app/accounts/user.ex

defmodule MyApp.Accounts.User do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    authorizers: [Ash.Policy.Authorizer],
    domain: MyApp.Accounts

  attributes do
    uuid_primary_key :id
  end

  actions do
    defaults [:read]
    
    read :get_by_subject do
      description "Get a user by the subject claim in a JWT"
      argument :subject, :string, allow_nil?: false
      get? true
      prepare AshAuthentication.Preparations.FilterBySubject
    end
  end

  authentication do
    tokens do
      enabled? true
      token_resource MyApp.Accounts.Token
      store_all_tokens? true
      signing_secret fn _, _ ->
        # This is a secret key used to sign tokens. See the note below on secrets management
        Application.fetch_env(:my_app, :token_signing_secret)
      end
    end

    add_ons do
      log_out_everywhere do
        apply_on_password_change? true
      end
    end
  end

  postgres do
    table "users"
    repo MyApp.Repo
  end

  # You can customize this if you wish, but this is a safe default that
  # only allows user data to be interacted with via AshAuthentication.
  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    policy always() do
      forbid_if always()
    end
  end
end
```

> ### The signing secret must not be committed to source control {: .warning}
>
> Proper management of secrets is outside the scope of this tutorial, but is
> absolutely crucial to the security of your application.

<!-- tabs-close -->

## Choose your strategies and add-ons

### `mix ash_authentication.add_strategy`

A mix task is provided to add strategies and add-ons to your application.
For now, this only supports the `password` strategy, but more will be added in the future.

```sh
mix ash_authentication.add_strategy password
```

#### Strategies

- [Password](/documentation/tutorials/password.md)
- [Github](/documentation/tutorials/github.md)
- [Google](/documentation/tutorials/google.md)
- [Magic Links](/documentation/tutorials/magic-links.md)
- [Auth0](/documentation/tutorials/auth0.md)
- Open ID: `AshAuthentication.Strategy.Oidc`
- OAuth2: `AshAuthentication.Strategy.OAuth2`

#### Add-Ons

- [Confirmation](/documentation/tutorials/confirmation.md): confirming changes to user accounts (i.e via email)
- UserIdentity: `AshAuthentication.UserIdentity`: supporting multiple social sign on identities & refreshing tokens

## Set up your Phoenix or Plug application

If you're using Phoenix, skip this section and go to
[Integrating Ash Authentication and Phoenix](https://hexdocs.pm/ash_authentication_phoenix/get-started.html)

In order for your users to be able to sign in, you will likely need to provide
an HTTP endpoint to submit credentials or OAuth requests to. Ash Authentication
provides `AshAuthentication.Plug` for this purposes. It provides a `use` macro
which handles routing of requests to the correct providers, and defines
callbacks for successful and unsuccessful outcomes.

Let's generate our plug:

```elixir
# lib/my_app/auth_plug.ex

defmodule MyApp.AuthPlug do
  use AshAuthentication.Plug, otp_app: :my_app

  def handle_success(conn, _activity, user, token) do
    if is_api_request?(conn) do
      conn
      |> send_resp(200, Jason.encode!(%{
        authentication: %{
          success: true,
          token: token
        }
      }))
    else
      conn
      |> store_in_session(user)
      |> send_resp(200, EEx.eval_string("""
      <h2>Welcome back <%= @user.email %></h2>
      """, user: user))
    end
  end

  def handle_failure(conn, _activity, _reason) do
    if is_api_request?(conn) do
      conn
      |> send_resp(401, Jason.encode!(%{
        authentication: %{
          success: false
        }
      }))
    else
      conn
      |> send_resp(401, "<h2>Incorrect email or password</h2>")
    end
  end

  defp is_api_request?(conn), do: "application/json" in get_req_header(conn, "accept")
end
```

Now that this is done, you can forward HTTP requests to it from your app's main
router using `forward "/auth", to: MyApp.AuthPlug` or similar.

Your generated auth plug module will also contain `load_from_session` and
`load_from_bearer` function plugs, which can be used to load users into assigns
based on the contents of the session store or `Authorization` header.

## Customizing Authentication Actions

Authentication strategies automatically generate actions like `register`, `sign_in`, etc. When customizing these actions, keep in mind:

### Required Authentication Changes

Always include the strategy's required changes when overriding actions:

```elixir
# Password registration
create :register_with_password do
  # Your custom arguments and logic...
  
  # Required for password strategy:
  change AshAuthentication.GenerateTokenChange
  change AshAuthentication.Strategy.Password.HashPasswordChange
end

# OAuth2 registration  
create :register_with_github do
  argument :user_info, :map, allow_nil?: false
  argument :oauth_tokens, :map, allow_nil?: false, sensitive?: true
  
  # Required for OAuth2:
  change AshAuthentication.GenerateTokenChange
  change AshAuthentication.Strategy.OAuth2.IdentityChange
  
  # Extract user data from OAuth response:
  change fn changeset, _ctx ->
    user_info = Ash.Changeset.get_argument(changeset, :user_info)
    Ash.Changeset.change_attributes(changeset, Map.take(user_info, ["email", "name"]))
  end
end
```

### Security for Authentication

Mark sensitive authentication data appropriately:

```elixir
attributes do
  # Identity fields - public for authentication UI
  attribute :email, :ci_string, allow_nil?: false, public?: true
  
  # Credentials - always sensitive, never public
  attribute :hashed_password, :string, allow_nil?: false, sensitive?: true, public?: false
end

actions do
  create :register do
    # Credential arguments - always sensitive
    argument :password, :string, allow_nil?: false, sensitive?: true
    argument :password_confirmation, :string, allow_nil?: false, sensitive?: true
  end
end
```

> ### Note on `public?: true` {: .info}
> 
> The `public?: true` option controls API visibility, not authentication requirements. 
> Identity fields like `:email` typically need `public?: true` for authentication UIs to work properly.

## Summary

In this guide we've learned how to install Ash Authentication, configure
resources and handle authentication HTTP requests.

You should now have an Ash application with working user authentication.

Up next, [Using with Phoenix](https://hexdocs.pm/ash_authentication_phoenix/get-started.html)
