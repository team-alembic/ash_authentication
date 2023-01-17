# GitHub Quick Start Guide

This is a _very quick_ tutorial on how to configure your application to use
GitHub for authentication.

First you need to configure an application in your [GitHub developer
settings](https://github.com/settings/developers):

  1. Click the "New OAuth App" button.
  2. Set your application name to something that identifies it.  You will likely
     need separate applications for development and production environments, so
     keep that in mind.
  3. Set "Homepage URL" appropriately for your application and environment.
  4. In the "Authorization callback URL" section,  add your callback URL.  The
     callback URL is generated from the following information:
      - The base URL of the application - in development that would be
        `http://localhost:4000/` but in production will be your application's
        URL.
      - The mount point of the auth routes in your router - we'll assume
        `/auth`.
      - The "subject name" of the resource being authenticated - we'll assume `user`.
      - The name of the strategy in your configuration.  By default this is
        `github`.

     This means that the callback URL should look something like
     `http://localhost:4000/auth/user/github/callback`.
  5. Do not set "Enable Device Flow" unless you know why you want this.
  6. Click "Register application".
  7. Click "Generate a new client secret".
  8. Copy the "Client ID" and "Client secret" somewhere safe, we'll need them
     soon.
  9. Click "Update application".

Next we can configure our resource (assuming you already have everything else
set up):

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource, extensions: [AshAuthentication]

  authentication do
    github do
      client_id MyApp.Secrets
      redirect_uri MyApp.Secrets
      client_secret MyApp.Secrets
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

  def secret_for([:authentication, :strategies, :github, :client_id], MyApp.Accounts.User, _) do
    get_config(:client_id)
  end

  def secret_for([:authentication, :strategies, :github, :redirect_uri], MyApp.Accounts.User, _) do
    get_config(:redirect_uri)
  end

  def secret_for([:authentication, :strategies, :github, :client_secret], MyApp.Accounts.User, _) do
    get_config(:client_secret)
  end

  defp get_config(key) do
    :my_app
    |> Application.get_env(:github, [])
    |> Keyword.fetch(key)
  end
end
```

The values for this configuration should be:

  * `client_id` - the client ID copied from the GitHub settings page.
  * `redirect_uri` - the URL to the generated auth routes in your application
    (eg `http://localhost:4000/auth`).
  * `client_secret` the client secret copied from the GitHub settings page.
