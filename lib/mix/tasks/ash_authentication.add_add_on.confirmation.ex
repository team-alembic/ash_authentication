# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddAddOn.Confirmation do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_add_on.confirmation"

    @shortdoc "Adds email confirmation to your user resource"

    @moduledoc """
    #{@shortdoc}

    Adds a confirmation add-on that monitors an identity field (defaults to email)
    and sends a confirmation email when a new user registers.

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` -  The user resource. Defaults to `YourApp.Accounts.User`
    * `--identity-field`, `-i` - The field to monitor for confirmation. Defaults to `email`
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [],
        schema: [
          accounts: :string,
          user: :string,
          identity_field: :string
        ],
        aliases: [
          a: :accounts,
          u: :user,
          i: :identity_field
        ],
        defaults: [
          identity_field: "email"
        ]
      }
    end

    def igniter(igniter) do
      options = parse_options(igniter)

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          igniter
          |> confirmation(options)

        {false, igniter} ->
          Igniter.add_issue(igniter, """
          User module #{inspect(options[:user])} was not found.

          Perhaps you have not yet installed ash_authentication?
          """)
      end
    end

    defp parse_options(igniter) do
      options =
        igniter.args.options
        |> Keyword.put_new_lazy(:accounts, fn ->
          Igniter.Project.Module.module_name(igniter, "Accounts")
        end)

      options
      |> Keyword.put_new_lazy(:user, fn ->
        Module.concat(options[:accounts], User)
      end)
      |> Keyword.update(:identity_field, :email, &String.to_atom/1)
      |> Keyword.update!(:accounts, &AshAuthentication.Igniter.maybe_parse_module/1)
      |> Keyword.update!(:user, &AshAuthentication.Igniter.maybe_parse_module/1)
    end

    defp confirmation(igniter, options) do
      sender = Module.concat(options[:user], Senders.SendNewUserConfirmationEmail)

      AshAuthentication.Igniter.add_new_add_on(
        igniter,
        options[:user],
        :confirm_new_user,
        :password,
        """
        confirmation :confirm_new_user do
          monitor_fields [:#{options[:identity_field]}]
          confirm_on_create? true
          confirm_on_update? false
          require_interaction? true
          confirmed_at_field :confirmed_at
          auto_confirm_actions [:sign_in_with_magic_link, :reset_password_with_token]
          sender #{inspect(sender)}
        end
        """
      )
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], :confirmed_at, """
      attribute :confirmed_at, :utc_datetime_usec
      """)
      |> create_new_user_confirmation_sender(sender, options)
    end

    defp create_new_user_confirmation_sender(igniter, sender, options) do
      case Igniter.Libs.Swoosh.list_mailers(igniter) do
        {igniter, [mailer]} ->
          {_web_module_exists?, use_web_module, igniter} =
            AshAuthentication.Igniter.web_module_use_line(igniter)

          Igniter.Project.Module.create_module(
            igniter,
            sender,
            ~s'''
            @moduledoc """
            Sends an email for a new user to confirm their email address.
            """

            use AshAuthentication.Sender
            #{use_web_module}

            import Swoosh.Email

            alias #{inspect(mailer)}

            @impl true
            def send(user, token, _) do
              new()
              # TODO: Replace with your email
              |> from({"noreply", "noreply@example.com"})
              |> to(to_string(user.email))
              |> subject("Confirm your email address")
              |> html_body(body([token: token]))
              |> #{List.last(Module.split(mailer))}.deliver!()
            end

            defp body(params) do
              url = url(~p"/confirm_new_user/\#{params[:token]}")

              """
              <p>Click this link to confirm your email:</p>
              <p><a href="\#{url}">\#{url}</a></p>
              """
            end
            '''
          )

        _ ->
          create_example_new_user_confirmation_sender(igniter, sender, options)
      end
    end

    defp create_example_new_user_confirmation_sender(igniter, sender, options) do
      {web_module_exists?, use_web_module, igniter} =
        AshAuthentication.Igniter.web_module_use_line(igniter)

      example_domain = AshAuthentication.Igniter.parent_module(options[:user])

      real_example =
        if web_module_exists? do
          """
          # Example of how you might send this email
          # #{inspect(example_domain)}.Emails.send_new_user_confirmation_email(
          #   user,
          #   token
          # )
          """
        end

      url =
        if use_web_module do
          "\#{url(~p\"/confirm_new_user?/\#{token}\")}"
        else
          "/confirm_new_user/\#{token}"
        end

      Igniter.Project.Module.create_module(
        igniter,
        sender,
        ~s'''
        @moduledoc """
        Sends an email for a new user to confirm their email address.
        """

        use AshAuthentication.Sender
        #{use_web_module}

        @impl true
        def send(_user, token, _) do
          #{real_example}
          IO.puts("""
          Click this link to confirm your email:

          #{url}
          """)
        end
        '''
      )
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddAddOn.Confirmation do
    @shortdoc "Adds email confirmation to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_add_on.confirmation' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
