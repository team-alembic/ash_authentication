# GitHub Tutorial

This is a quick tutorial on how to configure your application to use GitHub for authentication.

First you need to configure an application in your [GitHub developer settings](https://github.com/settings/developers):

1. Click the "New OAuth App" button.
2. Set your application name to something that identifies it. You will likely
   need separate applications for development and production environments, so
   keep that in mind.
3. Set "Homepage URL" appropriately for your application and environment.
4. In the "Authorization callback URL" section, add your callback URL. The
   callback URL is generated from the following information:

   - The base URL of the application - in development that would be
     `http://localhost:4000/` but in production will be your application's
     URL.
   - The mount point of the auth routes in your router - we'll assume
     `/auth`.
   - The "subject name" of the resource being authenticated - we'll assume `user`.
   - The name of the strategy in your configuration. By default this is
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
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  authentication do
    strategies do
      github do
        client_id MyApp.Secrets
        redirect_uri MyApp.Secrets
        client_secret MyApp.Secrets
      end
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

- `client_id` - the client ID copied from the GitHub settings page.
- `redirect_uri` - the URL to the generated auth routes in your application
  (eg `http://localhost:4000/auth`).
- `client_secret` the client secret copied from the GitHub settings page.

Lastly, we need to add a register action to your user resource. This is defined
as an upsert so that it can register new users, or update information for
returning users. The default name of the action is `register_with_` followed by
the strategy name. In our case that is `register_with_github`.

The register action takes two arguments, `user_info` and the `oauth_tokens`.

- `user_info` contains the [`GET /user` response from
  GitHub](https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user)
  which you can use to populate your user attributes as needed.
- `oauth_tokens` contains the [`POST /login/oauth/access_token` response from
  GitHub](https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps#response)
  - you may want to store these if you intend to call the GitHub API on behalf
    of the user.

```elixir
defmodule MyApp.Accounts.User do
  require Ash.Resource.Change.Builtins
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  # ...

  actions do
    create :register_with_github do
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

      # Required if you're using the password & confirmation strategies
      upsert_fields []
      change set_attribute(:confirmed_at, &DateTime.utc_now/0)
      change after_action(fn _changeset, user, _context ->
        case user.confirmed_at do
          nil -> {:error, "Unconfirmed user exists already"}
          _ -> {:ok, user}
        end
      end)
    end
  end

  # ...

end
```

Ensure you set the `hashed_password` to `allow_nil?` if you are also using the password strategy.

```elixir
defmodule MyApp.Accounts.User do
  # ...
  attributes do
    # ...
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true
  end
  # ...
end
```

And generate and run migrations in that case.

```bash
mix ash.codegen make_hashed_password_nullable
mix ash.migrate
```
