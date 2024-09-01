# Google Tutorial

This is a quick tutorial on how to configure Google authentication.

First you'll need a registered application in [Google Cloud](https://console.cloud.google.com/welcome), in order to get your OAuth 2.0 Client credentials.

1. On the Cloud's console **Quick access** section select **APIs & Services**, then **Credentials**
2. Click on **+ CREATE CREDENTIALS** and from the dropdown select **OAuth client ID**
3. From the google developers console, we will need: `client_id` & `client_secret`
4. Enter your callback uri under **Authorized redirect URIs**. E.g. `http://localhost:4000/auth/user/google/callback`.

Next we configure our resource to use google credentials:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  attributes do
    ...
  end

  authentication do
    strategies do
      google do
        client_id MyApp.Secrets
        redirect_uri MyApp.Secrets
        client_secret MyApp.Secrets
      end
    end
  end
end
```

Please check the guide on how to properly configure your Secrets
Then we need to define an action that will handle the oauth2 flow, for the google case it is `:register_with_google` it will handle both cases for our resource, user registration & login.

```elixir
defmodule MyApp.Accounts.User do
  require Ash.Resource.Change.Builtins
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  # ...
  actions do
    create :register_with_google do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :unique_email

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
