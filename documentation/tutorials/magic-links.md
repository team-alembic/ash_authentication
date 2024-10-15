# Magic Links Tutorial

## With a mix task

You can use `mix ash_authentication.add_strategy magic_link` to install this strategy.
The rest of the guide is in the case that you wish to proceed manually.

## Add the Magic Link Strategy to the User resource

```elixir
# ...

strategies do
  # add these lines -->
  magic_link do
    identity_field :email
    registration_enabled? true

    sender(Example.Accounts.User.Senders.SendMagicLink)
  end
  # <-- add these lines
end

# ...
```

### Registration Enabled

When registration is enabled, signing in with magic is a _create_ action that upserts the user by email.
This allows a user who does not exist to request a magic link and sign up with one action.

### Registration Disabled (default)

When registration is disabled, signing in with magic link is a _read_ action.

## Create an email sender and email template

Inside `/lib/example/accounts/user/senders/send_magic_link.ex`

```elixir
defmodule Example.Accounts.User.Senders.SendMagicLink do
  @moduledoc """
  Sends a magic link
  """
  use AshAuthentication.Sender
  use ExampleWeb, :verified_routes

  @impl AshAuthentication.Sender
  def send(user_or_email, token, _) do
    # will be a user if the token relates to an existing user
    # will be an email if there is no matching user (such as during sign up)
    Example.Accounts.Emails.deliver_magic_link(
      user_or_email,
      url(~p"/auth/user/magic_link/?token=#{token}")
    )
  end
end
```

Inside `/lib/example/accounts/emails.ex`

```elixir
# ...

def deliver_magic_link(user, url) do
  if !url do
    raise "Cannot deliver reset instructions without a url"
  end

  email = case user do
    %{email: email} -> email
    email -> email
  end

  deliver(email, "Magic Link", """
  <html>
    <p>
      Hi #{email},
    </p>

    <p>
      <a href="#{url}">Click here</a> to login.
    </p>
  <html>
  """)
end

# ...
```
