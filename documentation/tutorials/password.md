<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

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

## Reset request timing and account enumeration

When you configure `resettable` with a sender, the strategy adds a reset request
action. That action returns `:ok` whether or not the identity matches a user, so
the response body does not reveal which accounts exist. The response *time* does.
On a match, the action mints a reset token and then calls your sender inline. On a
miss, it returns straight away. There is no registration option here, so the miss
path always short-circuits. A synchronous SMTP or HTTP-API send adds tens to
hundreds of milliseconds, which is enough to tell the two paths apart.

An asynchronous sender closes that gap. Enqueue a job from your `send/3` callback
and return `:ok` straight away, then deliver the message from the job. That keeps
delivery latency off both paths. The callback's return value is ignored anyway, so
returning early gives up nothing — see `AshAuthentication.Sender`. The difference
then falls to one JWT signing operation, about 27 microseconds. Neither path
writes to the database unless you enable `store_all_tokens?`. At that size the
difference is not measurable across a network.
