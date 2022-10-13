# Getting Started with Authentication

## Get familiar with Ash resources

If you haven't already, read the getting started guide for Ash. This assumes that you already have resources set up, and only gives you the steps to _add_ AshAuthentication to your resources/apis.

## Bring in the `ash_authentication` dependency

```elixir
def deps()
  [
    # ...
    {:ash_authentication, "~> x.x"},
    # ...
  ]
end
```

Use `mix hex.info ash_authentication` to quickly find the latest version.

## Add the Authentication extension

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource, extensions: [AshAuthentication]

  authentication do
    api MyApp.Accounts
  end
end
```

## Supporting password authentication

Password authentication is provided by the `AshAuthentication.Identity` extension.

At a minimum you need a uniquely constrained "identity" field (eg `username`,
`email`, etc) and a string field within which to store the hashed password.

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource, extensions: [AshAuthentication, AshAuthentication.Identity]

  attributes do
    uuid_primary_key :id
    attribute :email, :ci_string, allow_nil?: false
    attribute :hashed_password, :string, allow_nil?: false, sensitive?: true
  end

  authentication do
    api MyApp.Accounts
  end

  identity_authentication do
    username_field :email
    hashed_password_field :hashed_password
  end

  identities do
    identity(:email, [:email])
  end
end
```
