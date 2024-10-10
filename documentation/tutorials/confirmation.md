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

You can add the upsert registration action(s) to the `auto_confirm_actions`
list, and add a change to those actions that sets `hashed_password` to `nil`. This will confirm users, and require them to reset
heir password before being able to use password authentication again.

#### Opt-out

You can set `prevent_hijacking? false` on the confirmation add-on to disable the automatic handling
described above. This is not recommended.

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

To make this work we need to create a new module `MyApp.Accounts.User.Senders.SendPasswordResetEmail`:

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
      url(~p"/auth/user/confirm_new_user?#{[confirm: token]}")
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

## Confirming changes to monitored fields

You may want to require a user to perform a confirmation when a certain field changes. For example if a user changes their email address we can send them a new confirmation request.

First, let's start by defining a new confirmation add-on in our resource:

```elixir
defmodule MyApp.Accounts.User do
  # ...

  authentication do
    # ...

    add_ons do
      confirmation :confirm_change do
        monitor_fields [:email]
        confirm_on_create? false
        confirm_on_update? true
        confirm_action_name :confirm_change
        sender MyApp.Accounts.User.Senders.SendEmailChangeConfirmationEmail
      end
    end
  end
end
```

> #### Why two confirmation configurations? {: .info}
>
> While you can perform both of these confirmations with a single confirmation add-on, in general the Ash philosophy is to be more explicit. Each confirmation will have it's own URL (based on the name) and tokens for one will not be able to be used for the other.

Next, let's define our new sender:

```elixir
defmodule MyApp.Accounts.User.Senders.SendEmailChangeConfirmationEmail do
  @moduledoc """
  Sends an email change confirmation email
  """
  use AshAuthentication.Sender
  use MyAppWeb, :verified_routes

  @impl AshAuthentication.Sender
  def send(user, token, _opts) do
    MyApp.Accounts.Emails.deliver_email_change_confirmation_instructions(
      user,
      url(~p"/auth/user/confirm_change?#{[confirm: token]}")
    )
  end
end
```

And our new email template:

```elixir
defmodule MyApp.Accounts.Emails do
  # ...

  def deliver_email_change_confirmation_instructions(user, url) do
    if !url do
      raise "Cannot deliver confirmation instructions without a url"
    end

    deliver(user.email, "Confirm your new email address", """
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

> #### Inhibiting changes {: .tip}
>
> Depending on whether you want the user's changes to be applied _before_ or _after_ confirmation, you can enable the [`inhibit_updates?` DSL option](documentation/dsls/DSL:-AshAuthentication.AddOn.Confirmation.md#authentication-add_ons-confirmation-inhibit_updates?).
>
> When this option is enabled, then any potential changes to monitored fields are instead temporarily stored in the [token resource](documentation/dsls/DSL:-AshAuthentication.TokenResource.md) and applied when the confirmation action is run.

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
