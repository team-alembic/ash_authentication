# Password Authentication

## With a mix task

You can use `mix ash_authentication.add_strategy password` to install this strategy.
The rest of the guide is in the case that you wish to proceed manually.

## Add Bcrypt To your dependencies

This step is not strictly necessary, but in the next major version of `AshAuthentication`,
`Bcrypt` will be an optional dependency. This will make that upgrade slightly easier.

```elixir
{:bcrypt_elixir, "~> 3.0"}
```

## Add Attributes

Add an `email` (or `username`) and `hashed_password` attribute to your user resource.

```elixir
# lib/my_app/accounts/user.ex
attributes do
  ...
  attribute :email, :ci_string, allow_nil?: false, public?: true
  attribute :hashed_password, :string, allow_nil?: false, sensitive?: true
end
```

Ensure that the `email` (or username) is unique.

```elixir
# lib/my_app/accounts/user.ex
identities do
  identity :unique_email, [:email]
  # or
  identity :unique_username, [:username]
end
```

## Add the password strategy

Configure it to use the `:email` or `:username` as the identity field.

```elixir
# lib/my_app/accounts/user.ex
authentication do
  ...
  strategies do
    password :password do
      identity_field :email
      # or
      identity_field :username
    end
  end
end
```

Now we have enough in place to register and sign-in users using the
`AshAuthentication.Strategy` protocol.
