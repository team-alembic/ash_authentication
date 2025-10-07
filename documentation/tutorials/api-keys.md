<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# API Keys

## A note on API Keys

API keys are generated using `AshAuthentication.Strategy.ApiKey.GenerateApiKey`. See the module docs for more information.
The API key is generated using a random byte string and a prefix. The prefix is used to generate a key that is compliant with secret scanning. You can use this to set up an endpoint that will automatically revoke leaked tokens, which is an extremely powerful and useful security feature. We only store a hash of the api key. The plaintext api key is only available in `api_key.__metadata__.plaintext_api_key` immediately after creation.

See [the guide on Github](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partnership-program/secret-scanning-partner-program) for more information.

Api key expiration/validity is otherwise up to you. The configured `api_key_relationship` should include those rules in the filter.
For example:

```elixir
has_many :valid_api_keys, MyApp.Accounts.ApiKey do
  filter expr(valid)
end
```

## Installation

<!-- tabs-open -->

### With Igniter (recommended)

Use `mix ash_authentication.add_strategy api_key` to install this strategy, and modify the generated resource
to suit your needs.

### Manually

#### Create an API key resource

```elixir
defmodule MyApp.Accounts.ApiKey do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:user_id, :expires_at]
      change {AshAuthentication.Strategy.ApiKey.GenerateApiKey, prefix: :myapp, hash: :api_key_hash}
    end
  end

  attributes do
    uuid_primary_key :id
    attribute :api_key_hash, :binary do
      allow_nil? false
      sensitive? true
    end

    # In this example, all api keys have an expiration
    # Feel free to rework this however you please
    attribute :expires_at, :utc_datetime_usec do
      allow_nil? false
    end
  end

  relationships do
    belongs_to :user, MyApp.Accounts.User do
      allow_nil? false
    end
  end

  calculations do
    calculate :valid, :boolean, expr(expires_at > now())
  end

  identities do
    identity :unique_api_key, [:api_key_hash]
  end

  policies do
    # Allow AshAuthentication to work with api keys as necessary
    bypass always() do
      authorize_if AshAuthentication.Checks.AshAuthenticationInteraction
    end
  end
end
```

#### Add the strategy to your user

```elixir
authentication do
  ...
  strategies do
    api_key do
      api_key_relationship :valid_api_keys
    end
  end
end
```

#### Relate users to valid api keys

```elixir
relationships do
  has_many :valid_api_keys, MyApp.Accounts.ApiKey do
    filter expr(valid)
  end
end
```

#### Add the sign_in_with_api_key action

Add the action to your user resource

```elixir
read :sign_in_with_api_key do
  argument :api_key, :string, allow_nil?: false
  prepare AshAuthentication.Strategy.ApiKey.SignInPreparation
end
```

#### Use the plug in your router/plug pipeline

See `AshAuthentication.Strategy.ApiKey.Plug` for all available options.

In Phoenix, for example, you might add this plug to your
`:api` pipeline.

```elixir
pipeline :api do
  ...
  plug AshAuthentication.Strategy.ApiKey.Plug,
    resource: MyApp.Accounts.User
end
```

<!-- tabs-close -->
