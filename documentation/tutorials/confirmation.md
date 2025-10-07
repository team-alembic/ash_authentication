<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Confirmation Tutorial

This add-on allows you to confirm changes to a user record by generating and
sending them a confirmation token which they must submit before allowing the
change to take place.

In this tutorial we'll assume that you have a `User` resource which uses `email` as it's user identifier.
We'll show you how to confirm a new user on sign-up and also require them to confirm if they wish to change their email address.

## Important security notes

If you are using multiple strategies that use emails, where one of the strategy has an upsert registration (like social sign-up, magic link registration),
then you _must_ use the confirmation add-on to prevent account hijacking, as described below.

Example scenario:

- Attacker signs up with email of their target and a password, but does not confirm their email.
- Their target signs up with google or magic link, etc, which upserts the user, and sets `confirmed_at` to `true`.
- Now, the user has created an account but the attacker has access via the password they originally set.

### How to handle this?

#### Automatic Handling

The confirmation add-on prevents this by default by not allowing an upsert action to set `confirmed_at`, if there is
a matching record that has `confirmed_at` that is currently `nil`. This allows you to show a message to the user like
"You signed up with a different method. Please sign in with the method you used to sign up."

#### auto_confirming and clearing the password on upsert

An alternative is to clear the user's password on upsert. To do this, you would want to ensure the following things are true:

- The upsert registration action(s) are in the `auto_confirm_actions` (which you want anyway)
- The upsert registration action(s) set `hashed_password` to `nil`, removing any access an attacker may have had
- The `prevent_hijacking?` option is set to `false` on the confirmation add on and the auth strategies you are using.
- A user cannot access your application or take any action without a confirmed account. For example, redirecting to a "please confirm your account" page.

Why do you have to ensure that no actions can be taken without a confirmed account?

This does technically remove any access that the attacker may have had from the account, but we don't suggest taking this approach
unless you are absolutely sure that you know what you are doing. For example, lets say you have an app that shows where the user is
in the world, or where their friends are in the world. Lets say you also allow configuring a phone number to receive text notifications
when they are near one of their friends. An attacker could sign up with a password, and configure their phone number. Then, their target
signs up with Oauth or magic link, adds some friends, but doesn't notice that a phone number is configured.

Now the attacker is getting text messages about where the user and/or their friends are.

#### Opt-out

You can set `prevent_hijacking? false` on either the confirmation add-on, or your strategy to disable the automatic handling
described above, and not follow the steps recommended in the section section above. This is not recommended.

## Tutorial

Here's the user resource we'll be starting with:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  attributes do
    uuid_primary_key :id
    attribute :email, :ci_string, allow_nil?: false, public?: true, sensitive?: true
    attribute :hashed_password, :string, allow_nil?: false, public?: false, sensitive?: true
  end

  authentication do
    strategies do
      password :password do
        identity_field :email
        hashed_password_field :hashed_password
      end
    end
  end

  identities do
    identity :unique_email, [:email]
  end
end
```

## Confirming newly registered users

First we start by adding the confirmation add-on to your existing authentication DSL:

```elixir
defmodule MyApp.Accounts.User do
  # ...

  authentication do
    # ...

    add_ons do
      confirmation :confirm_new_user do
        monitor_fields [:email]
        confirm_on_create? true
        confirm_on_update? false
        require_interaction? true
        sender MyApp.Accounts.User.Senders.SendNewUserConfirmationEmail
      end
    end
  end
end
```

Next we will have to generate and run migrations to add confirmed_at column to user resource

```bash
mix ash.codegen account_confirmation
```

To make this work we need to create a new module `MyApp.Accounts.User.Senders.SendNewUserConfirmationEmail`:

```elixir
defmodule MyApp.Accounts.User.Senders.SendNewUserConfirmationEmail do
  @moduledoc """
  Sends an email confirmation email
  """
  use AshAuthentication.Sender
  use MyAppWeb, :verified_routes

  @impl AshAuthentication.Sender
  def send(user, token, _opts) do
    MyApp.Accounts.Emails.deliver_email_confirmation_instructions(
      user,
      url(~p"/confirm_new_user/#{token}")
    )
  end
end
```

We also need to create a new email template:

```elixir
defmodule Example.Accounts.Emails do
  @moduledoc """
  Delivers emails.
  """

  import Swoosh.Email

  def deliver_email_confirmation_instructions(user, url) do
    if !url do
      raise "Cannot deliver confirmation instructions without a url"
    end

    deliver(user.email, "Confirm your email address", """
      <p>
        Hi #{user.email},
      </p>

      <p>
        Someone has tried to register a new account using this email address.
        If it was you, then please click the link below to confirm your identity. If you did not initiate this request then please ignore this email.
      </p>

      <p>
        <a href="#{url}">Click here to confirm your account</a>
      </p>
    """)
  end

  # For simplicity, this module simply logs messages to the terminal.
  # You should replace it by a proper email or notification tool, such as:
  #
  #   * Swoosh - https://hexdocs.pm/swoosh
  #   * Bamboo - https://hexdocs.pm/bamboo
  #
  defp deliver(to, subject, body) do
    IO.puts("Sending email to #{to} with subject #{subject} and body #{body}")

    new()
    |> from({"Zach", "zach@ash-hq.org"}) # TODO: Replace with your email
    |> to(to_string(to))
    |> subject(subject)
    |> put_provider_option(:track_links, "None")
    |> html_body(body)
    |> MyApp.Mailer.deliver!()
  end
end
```

Provided you have your authentication routes hooked up either via `AshAuthentication.Plug` or [`AshAuthentication.Phoenix.Router`](https://hexdocs.pm/ash_authentication_phoenix/AshAuthentication.Phoenix.Router.html) then the user will be confirmed when the token is submitted.

## Blocking unconfirmed users from logging in

The previous section explained how to confirm a user account. AshAuthentication now includes a directive in the [DSL](https://hexdocs.pm/ash_authentication/dsl-ashauthentication-strategy-password.html#authentication-strategies-password-require_confirmed_with) that allows you to require account confirmation before a user can log in.

This can be a nice layer of protection to lock down your application, but consider
instead allowing unconfirmed users to use your application in a partial state.
This is often a better UX. This would involve adding a plug to your router,
for example, that redirects users to a home page that requests that they confirm
their account. Alternatively, you can just leverage their confirmation status
to allow or disallow certain actions.

> #### Must add error handling {: .warning}
>
> Your AuthController will begin getting a new error in the failure callback:
> `AshAuthentication.Errors.UnconfirmedUser` when this setting is enabled.. You'll need to handle this to show a new flash message.

For example:

```
authentication do
  ...
  add_ons do
    confirmation :confirm_new_user do
      ...
      confirmed_at_field :confirmed_at
    end
  end

  strategies do
    strategy :password do
      ...
      # Require confirmation using the specified field
      require_confirmed_with :confirmed_at
    end
  end
end
```

With this configuration, users whose `confirmed_at` field is `nil` will not be able to log in.

*Note:* It is currently the developer’s responsibility to handle this scenario - for example, by redirecting the user to a page that explains the situation and possibly offers an option to request a new confirmation email if the original one was lost.

If `require_confirmed_with` is not set or set to `nil`, no confirmation check is enforced - unconfirmed users will be allowed to log in.

## Confirming changes to monitored fields

You may want to require a user to perform a confirmation when a certain field changes. For example if a user changes their email address we can send them a new confirmation request.

First, let's start by defining a new confirmation add-on in our resource.

```elixir
defmodule MyApp.Accounts.User do
  # ...

  authentication do
    # ...

    add_ons do
      confirmation :confirm_email_change do
        monitor_fields [:email]
        confirm_on_create? false
        confirm_on_update? true
        inhibit_updates? true
        confirmed_at_field :email_change_confirmed_at
        confirm_action_name :confirm_email_change
        require_interaction? true
        sender MyApp.Accounts.User.Senders.SendEmailChangeConfirmationEmail
      end
    end
  end
end
```

We set `confirm_on_create? false` and `confirm_on_update? true` so that this only applies when an existing user changes their email address, and not for new users.

We specify `confirmed_at_field` so that the state of this confirmation is kept separate to the new user confirmation.  If we leave this out, the same default `confirmed_at_field` would be used, and then a user who has changed but not yet confirmed their email address would be in the same unconfirmed state as when they have created their account and not completed the initial confirmation.

`inhibit_updates? true` causes any changes to be stored temporarily in the [token resource](documentation/dsls/DSL-AshAuthentication.TokenResource.md), and are applied to the `user` resource only upon confirmation.  Without this option, a change to the `email` attribute is applied immediately

Next, let's define our new sender:

```elixir
defmodule MyApp.Accounts.User.Senders.SendEmailChangeConfirmationEmail do
  @moduledoc """
  Sends an email change confirmation email
  """
  use AshAuthentication.Sender
  use MyAppWeb, :verified_routes

  @impl AshAuthentication.Sender
  def send(user, token, opts) do
    {changeset, _opts} = Keyword.pop!(opts, :changeset)
    new_email_address = changeset.attributes.email

    MyApp.Accounts.Emails.deliver_email_change_confirmation_instructions(
      user,
      new_email_address,
      url(~p"/auth/user/confirm_change?#{[confirm: token]}")
    )
  end
end
```

And our new email template:

```elixir
defmodule MyApp.Accounts.Emails do
  # ...

  def deliver_email_change_confirmation_instructions(user, new_email_address, url) do
    if !url do
      raise "Cannot deliver confirmation instructions without a url"
    end

    deliver(user.new_email_address, "Confirm your new email address", """
      <p>
        Hi #{user.email},
      </p>

      <p>
        You recently changed your email address. Please confirm it.
      </p>

      <p>
        <a href="#{url}">Click here to confirm your new email address</a>
      </p>
    """)
  end

  # ...
end
```

Note that we send this to the user's *new* email address in the changeset from the update action that triggered this confirmation.  You may also want to send a notification to the user's *current* email address, as a security measure, which you can do from the same sender.

## Customising the confirmation action

By default Ash Authentication will generate an update action for confirmation automatically (named `:confirm` unless you change it). You can manually implement this action in order to change it's behaviour and AshAuthentication will validate that the required changes are also present.

For example, here's an implementation of the `:confirm_change` action mentioned above, which adds a custom change that updates a remote CRM system with the user's new address.

```elixir
defmodule MyApp.Accounts.User do
  # ...

  actions do
    # ...

    update :confirm_change do
      argument :confirm, :string, allow_nil?: false, public?: true
      accept [:email]
      require_atomic? false
      change AshAuthentication.AddOn.Confirmation.ConfirmChange
      change AshAuthentication.GenerateTokenChange
      change MyApp.UpdateCrmSystem, only_when_valid?: true
    end
  end
end
```
