# Auth0 Tutorial

This is a quick tutorial on how to configure your application to use Auth0 for authentication.

First, you need to configure an application in [the Auth0 dashboard](https://manage.auth0.com/) using the following steps:

1. Click "Create Application".
2. Set your application name to something that identifies it. You will likely
   need separate applications for development and production environments, so
   keep that in mind.
3. Select "Regular Web Application" and click "Create".
4. Switch to the "Settings" tab.
5. Copy the "Domain", "Client ID" and "Client Secret" somewhere safe - we'll need them soon.
6. In the "Allowed Callback URLs" section, add your callback URL. The callback URL is generated from the following information:

   - The base URL of the application - in development that would be
     `http://localhost:4000/` but in production will be your application's
     URL.
   - The mount point of the auth routes in your router - we'll assume
     `/auth`.
   - The "subject name" of the resource being authenticated - we'll assume `user`.
   - The name of the strategy in your configuration. By default this is
     `auth0`.

   This means that the callback URL should look something like
   `http://localhost:4000/auth/user/auth0/callback`.

7. Set "Allowed Web Origins" to your application's base URL.
8. Click "Save Changes".

Next we can configure our resource:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  authentication do
    strategies do
      auth0 do
        client_id MyApp.Secrets
        redirect_uri MyApp.Secrets
        client_secret MyApp.Secrets
        base_url MyApp.Secrets
      end
    end
  end
end
```

Because all the configuration values should be kept secret (ie the `client_secret`) or are likely to be different for each environment we use the `AshAuthentication.Secret` behaviour to provide them. In this case we're delegating to the OTP application environment, however you may want to use a system environment variable or some other secret store (eg Vault).

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

  def secret_for([:authentication, :strategies, :auth0, :base_url], MyApp.Accounts.User, _) do
    get_config(:base_url)
  end

  defp get_config(key) do
    :my_app
    |> Application.fetch_env!(:auth0)
    |> Keyword.fetch!(key)
    |> then(&{:ok, &1})
  end
end
```

The values for this configuration should be:

- `client_id` - the client ID copied from the Auth0 settings page.
- `redirect_uri` - the URL to the generated auth routes in your application (eg `http://localhost:4000/auth`).
- `client_secret` the client secret copied from the Auth0 settings page.
- `base_url` - the "domain" value copied from the Auth0 settings page prefixed with `https://` (eg `https://dev-yu30yo5y4tg2hg0y.us.auth0.com`).

Lastly, we need to add a register action to your user resource. This is defined as an upsert so that it can register new users, or update information for returning users. The default name of the action is `register_with_` followed by the strategy name. In our case that is `register_with_auth0`.

The register action takes two arguments, `user_info` and the `oauth_tokens`.

- `user_info` contains the [`GET /userinfo` response from Auth0](https://auth0.com/docs/api/authentication#get-user-info) which you can use to populate your user attributes as needed.
- `oauth_tokens` contains the [`POST /oauth/token` response from Auth0](https://auth0.com/docs/api/authentication#get-token) - you may want to store these if you intend to call the Auth0 API on behalf of the user.

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  # ...

  actions do
    create :register_with_auth0 do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :unique_email

      # Required if you have token generation enabled.
      change AshAuthentication.GenerateTokenChange

      # Required if you have the `identity_resource` configuration enabled.
      change AshAuthentication.Strategy.OAuth2.IdentityChange

      change fn changeset, _ ->
        user_info = Ash.Changeset.get_argument(changeset, :user_info)

        Ash.Changeset.change_attributes(changeset, Map.take(user_info, ["email"]))
      end
    end
  end

  # ...

end
```
