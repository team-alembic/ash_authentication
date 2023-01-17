# Auth0 Quick Start Guide

This is a _very quick_ tutorial on how to configure your application to use
Auth0 for authentication.

First, you need to configure an application in [the Auth0
dashboard](https://manage.auth0.com/) using the following steps:

  1. Click "Create Application".
  2. Set your application name to something that identifies it.  You will likely
     need separate applications for development and production environments, so
     keep that in mind.
  3. Select "Regular Web Application" and click "Create".
  4. Switch to the "Settings" tab.
  5. Copy the "Domain", "Client ID" and "Client Secret" somewhere safe - we'll
     need them soon.
  6. In the "Allowed Callback URLs" section, add your callback URL.  The
     callback URL is generated from the following information:
      - The base URL of the application - in development that would be
        `http://localhost:4000/` but in production will be your application's
        URL.
      - The mount point of the auth routes in your router - we'll assume
        `/auth`.
      - The "subject name" of the resource being authenticated - we'll assume `user`.
      - The name of the strategy in your configuration.  By default this is
        `auth0`.

     This means that the callback URL should look something like
     `http://localhost:4000/auth/user/auth0/callback`.
  7. Set "Allowed Web Origins" to your application's base URL.
  8. Click "Save Changes".

Next we can configure our resource (assuming you already have everything else
set up):

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource, extensions: [AshAuthentication]

  authentication do
    auth0 do
      client_id MyApp.Secrets
      redirect_uri MyApp.Secrets
      client_secret MyApp.Secrets
      site MyApp.Secrets
    end
  end
end
```

Because all the configuration values should be kept secret (ie the
`client_secret`) or are likely to be different for each environment we use the
`AshAuthentication.Secret` behaviour to provide them. In this case we're
delegating to the OTP application environment, however you may want to use a
system environment variable or some other secret store (eg Vault).

```elixir
defmodule MyApp.Secrets do
  use AshAuthentication.Secret

  def secret_for([:authentication, :strategies, :auth0, :client_id], MyApp.Accounts.User, _) do
    get_config(:client_id)
  end

  def secret_for([:authentication, :strategies, :auth0, :redirect_uri], MyApp.Accounts.User, _) do
    get_config(:redirect_uri)
  end

  def secret_for([:authentication, :strategies, :auth0, :client_secret], MyApp.Accounts.User, _) do
    get_config(:client_secret)
  end

  def secret_for([:authentication, :strategies, :auth0, :site], MyApp.Accounts.User, _) do
    get_config(:site)
  end

  defp get_config(key) do
    :my_app
    |> Application.get_env(:auth0, [])
    |> Keyword.fetch(key)
  end
end
```

The values for this configuration should be:

  * `client_id` - the client ID copied from the Auth0 settings page.
  * `redirect_uri` - the URL to the generated auth routes in your application
    (eg `http://localhost:4000/auth`).
  * `client_secret` the client secret copied from the Auth0 settings page.
  * `site` - the "domain" value copied from the Auth0 settings page prefixed
    with `https://` (eg `https://dev-yu30yo5y4tg2hg0y.us.auth0.com`).
