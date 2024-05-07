# Magic Links Tutorial

This is a quick tutorial to get you up and running on Magic Links.
This assumes you've set up `ash_authentication` and [password reset](https://ash-hq.org/docs/guides/ash_authentication_phoenix/latest/tutorials/getting-started-with-ash-authentication-phoenix) in your Phoenix project.

## Add the Magic Link Strategy to the User resource

```elixir
# ...

strategies do
  password :password do
    identity_field(:email)

    resettable do
      sender(Example.Accounts.User.Senders.SendPasswordResetEmail)
    end
  end

  # add these lines -->
  magic_link do
    identity_field :email
    sender(Example.Accounts.User.Senders.SendMagicLink)
  end
  # <-- add these lines
end

# ...
```

## Create and email sender and email template

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
