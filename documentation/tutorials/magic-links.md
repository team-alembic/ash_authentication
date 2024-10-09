# Magic Links Tutorial

This is a quick tutorial to get you up and running on Magic Links. This assumes you've set up `ash_authentication` already.

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

When registration is enabled, requesting an email is a _create_ action that upserts the user by email.
This allows a user who does not exist to request a magic link and sign up with one action.

### Registration Disabled (default)

When registration is disabled, requesting an email is a _read_ action that invokes the sender only if a user
was found.

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
  def send(user, token, _) do
    Example.Accounts.Emails.deliver_magic_link(
      user,
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

  deliver(user.email, "Magic Link", """
  <html>
    <p>
      Hi #{user.email},
    </p>

    <p>
      <a href="#{url}">Click here</a> to login.
    </p>
  <html>
  """)
end

# ...
```
