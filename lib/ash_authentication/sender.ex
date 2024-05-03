defmodule AshAuthentication.Sender do
  @moduledoc ~S'''
  A module to implement sending of a token to a user.

  Allows you to glue sending of instructions to
  [swoosh](https://hex.pm/packages/swoosh),
  [ex_twilio](https://hex.pm/packages/ex_twilio) or whatever notification system
  is appropriate for your application.

  Note that the return value and any failures are ignored.  If you need retry
  logic, etc, then you should implement it in your sending system.

  ## Example

  Implementing as a module:

  ```elixir
  defmodule MyApp.PasswordResetSender do
    use AshAuthentication.Sender
    import Swoosh.Email

    def send(user, reset_token, _opts) do
      new()
      |> to({user.name, user.email})
      |> from({"Doc Brown", "emmet@brown.inc"})
      |> subject("Password reset instructions")
      |> html_body("""
        <h1>Password reset instructions</h1>
        <p>
          Hi #{user.name},<br />

          Someone (maybe you) has requested a password reset for your account.
          If you did not initiate this request then please ignore this email.
        </p>
        <a href="https://example.com/user/password/reset?#{URI.encode_query(reset_token: reset_token)}\">
          Click here to reset
        </a>
      """)
      |> MyApp.Mailer.deliver()
    end
  end

  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    authentication do
      strategies do
        password :password do
          resettable do
            sender MyApp.PasswordResetSender
          end
        end
      end
    end
  end
  ```

  You can also implement it directly as a function:

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    authentication do
      strategies do
        password :password do
          resettable do
            sender fn user, token ->
              MyApp.Mailer.send_password_reset_email(user, token)
            end
          end
        end
      end
    end
  end
  ```
  '''

  alias Ash.Resource

  @doc """
  Sending callback.

  This function will be called with the user, the token and any options passed
  to the module in the DSL.
  """
  @callback send(user :: Resource.record(), token :: String.t(), opts :: list) :: :ok

  @doc false
  @spec __using__(any) :: Macro.t()
  defmacro __using__(_) do
    quote do
      @behaviour AshAuthentication.Sender
    end
  end
end
