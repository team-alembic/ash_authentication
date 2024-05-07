# Google Tutorial

This is a quick tutorial on how to configure Google authentication.

First you'll need a registered application in [Google Cloud](https://console.cloud.google.com/welcome), in order to get your OAuth 2.0 Client credentials.

1. On the Cloud's console **Quick access** section select **APIs & Services**, then **Credentials**
2. Click on **+ CREATE CREDENTIALS** and from the dropdown select **OAuth client ID**
3. From the google developers console, we will need: `client_id` & `client_secret`

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
      oauth2 :google do
        client_id MyApp.Secrets
        redirect_uri MyApp.Secrets
        client_secret MyApp.Secrets end
        base_url MyApp.Secrets
      end
    end
  end
end
```

Please check the guide on how to properly configure your Secrets
Then we need to define an action that will handle the oauth2 flow, for the google case it is `:register_with_google` it will handle both cases for our resource, user registration & login.

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  # ...
  actions do
    create :register_with_google do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :email

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
