# Confirmation Tutorial

This is a quick tutorial on how to configure your application to enable confirmation.

In this tutorial we'll assume that you have a `User` resource which uses `email` as it's user identifier. We'll show you how to confirm a new user on sign-up and also require them to confirm if they wish to change their email address.

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
        confirm_action_name :confirm_new_user
        sender MyApp.NewUserConfirmationSender
      end
    end
  end
end
```

Next we will define our "sender" module using `Swoosh`:

```elixir
defmodule MyApp.NewUserConfirmationSender do
  use AshAuthentication.Sender

  def send(user, token, _opts) do
    new()
    |> to(user.email)
    |> from({"MyApp Admin", "support@myapp.inc"})
    |> subject("Confirm your email address")
    |> html_body("""
      <p>
        Hi!<br />

        Someone has tried to register a new account at <a href="https://myapp.inc">MyApp</a>.
        If it was you, then please click the link below to confirm your identity.  If you did not initiate this request then please ignore this email.
      </p>
      <p>
        <a href="https://myapp.inc/auth/user/confirm_new_user?#{URI.encode_query(token: @token)}">Click here to confirm your account</a>
      </p>
    """)
    |> MyApp.Mailer.deliver()
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
        sender MyApp.EmailChangeConfirmationSender
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
defmodule MyApp.NewUserConfirmationSender do
  use AshAuthentication.Sender

  def send(user, token, _opts) do
    new()
    |> to(user.email)
    |> from({"MyApp Admin", "support@myapp.inc"})
    |> subject("Confirm your new email address")
    |> html_body("""
      <p>
        Hi!<br />

        You recently changed your email address on <a href="https://myapp.inc">MyApp</a>.  Please confirm it.
      </p>
      <p>
        <a href="https://myapp.inc/auth/user/confirm_change?#{URI.encode_query(token: @token)}">Click here to confirm your new email address</a>
      </p>
    """)
    |> MyApp.Mailer.deliver()
  end
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

      change AshAuthentication.AddOn.Confirmation.ConfirmChange
      change AshAuthentication.GenerateTokenChange
      change MyApp.UpdateCrmSystem, only_when_valid?: true
    end
  end
end
```
