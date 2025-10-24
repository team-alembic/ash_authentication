# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.Gen.Strategy.MagicLink do
    use Igniter.Mix.Task

    @example "mix ash_authentication.gen.strategy.magic_link"
    @shortdoc "Adds the magic link strategy to your user resource"

    @moduledoc """
    #{@shortdoc}

    ## Example
    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` - The user resource. Defaults to `YourApp.Accounts.User`
    * `--identity-field`, `-i` - The field on the user resource that will be used to identify the user. Defaults to `email`.
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        schema: [
          user: :string,
          identity_field: :string
        ],
        aliases: [
          u: :user,
          i: :identity_field
        ],
        defaults: [
          identity_field: "email"
        ]
      }
    end

    def igniter(igniter) do
      default_user = Igniter.Project.Module.module_name(igniter, "Accounts.User")

      options =
        igniter.args.options
        |> Keyword.update(:identity_field, :email, &String.to_atom/1)
        |> Keyword.update(:user, default_user, &Igniter.Project.Module.parse/1)

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          igniter
          |> generate(options)
          |> Ash.Igniter.codegen("add_magic_link_auth")

        {false, igniter} ->
          Igniter.add_issue(igniter, """
          User module #{inspect(options[:user])} was not found.

          Perhaps you have not yet installed ash_authentication?
          """)
      end
    end

    defp generate(igniter, options) do
      if options[:identity_field] != :email do
        Mix.shell().error("""
        Could not add magic link strategy with identity field #{inspect(options[:identity_field])}.

        Please run `mix ash_authentication.gen.strategy.magic_link` without specifying a default
        """)

        exit({:shutdown, 1})
      end

      sender = Module.concat(options[:user], Senders.SendMagicLinkEmail)

      igniter
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], options[:identity_field], """
      attribute :#{options[:identity_field]}, :ci_string do
        allow_nil? false
        public? true
      end
      """)
      |> make_hashed_password_optional(options)
      |> ensure_identity(options)
      |> ensure_get_by_action(options)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :sign_in_with_magic_link, """
      create :sign_in_with_magic_link do
        description "Sign in or register a user with magic link."

        argument :token, :string do
          description "The token from the magic link that was sent to the user"
          allow_nil? false
        end

        upsert? true
        upsert_identity :unique_#{options[:identity_field]}
        upsert_fields [:#{options[:identity_field]}]

        # Uses the information from the token to create or sign in the user
        change AshAuthentication.Strategy.MagicLink.SignInChange

        metadata :token, :string do
          allow_nil? false
        end
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], :request_magic_link, """
      action :request_magic_link do
        argument :#{options[:identity_field]}, :ci_string do
          allow_nil? false
        end

        run AshAuthentication.Strategy.MagicLink.Request
      end
      """)
      |> AshAuthentication.Igniter.add_new_strategy(options[:user], :magic_link, :magic_link, """
      magic_link do
        identity_field :#{options[:identity_field]}
        registration_enabled? true
        require_interaction? true

        sender #{inspect(sender)}
      end
      """)
      |> create_new_magic_link_sender(sender, options)
    end

    defp make_hashed_password_optional(igniter, options) do
      Igniter.Project.Module.find_and_update_module!(igniter, options[:user], fn zipper ->
        with {:ok, zipper} <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(
                 zipper,
                 :attributes,
                 1
               ),
             {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper),
             {:ok, zipper} <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(
                 zipper,
                 :attribute,
                 [1, 2, 3],
                 &Igniter.Code.Function.argument_equals?(&1, 0, :hashed_password)
               ),
             {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper),
             {:ok, zipper} <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(
                 zipper,
                 :allow_nil?,
                 1,
                 &Igniter.Code.Function.argument_equals?(&1, 0, false)
               ) do
          {:ok, Sourceror.Zipper.remove(zipper)}
        else
          _ ->
            {:ok, zipper}
        end
      end)
    end

    defp ensure_identity(igniter, options) do
      Ash.Resource.Igniter.add_new_identity(
        igniter,
        options[:user],
        :"unique_#{options[:identity_field]}",
        """
        identity :unique_#{options[:identity_field]}, [:#{options[:identity_field]}]
        """
      )
    end

    defp ensure_get_by_action(igniter, options) do
      Ash.Resource.Igniter.add_new_action(
        igniter,
        options[:user],
        :"get_by_#{options[:identity_field]}",
        """
        read :get_by_#{options[:identity_field]} do
          description "Looks up a user by their #{options[:identity_field]}"
          get_by :#{options[:identity_field]}
        end
        """
      )
    end

    defp create_new_magic_link_sender(igniter, sender, options) do
      case Igniter.Libs.Swoosh.list_mailers(igniter) do
        {igniter, [mailer]} ->
          {_web_module_exists?, use_web_module, igniter} = create_use_web_module(igniter)

          url =
            if use_web_module do
              "\#{url(~p\"/magic_link/\#{params[:token]}\")}"
            else
              "/auth/user/magic_link?token=\#{params[:token]}"
            end

          Igniter.Project.Module.create_module(igniter, sender, ~s'''
          @moduledoc """
          Sends a magic link email
          """

          use AshAuthentication.Sender
          #{use_web_module}

          import Swoosh.Email
          alias #{inspect(mailer)}

          @impl true
          def send(user_or_email, token, _) do
            # if you get a user, its for a user that already exists.
            # if you get an email, then the user does not yet exist.

            email =
              case user_or_email do
                %{email: email} -> email
                email -> email
              end

            new()
            # TODO: Replace with your email
            |> from({"noreply", "noreply@example.com"})
            |> to(to_string(email))
            |> subject("Your login link")
            |> html_body(body([token: token, email: email]))
            |> #{List.last(Module.split(mailer))}.deliver!()
          end

          defp body(params) do
            # NOTE: You may have to change this to match your magic link acceptance URL.

            """
            <p>Hello, \#{params[:email]}! Click this link to sign in:</p>
            <p><a href="#{url}">#{url}</a></p>
            """
          end
          ''')

        _ ->
          create_example_new_magic_link_sender(igniter, sender, options)
      end
    end

    defp create_example_new_magic_link_sender(igniter, sender, options) do
      {web_module_exists?, use_web_module, igniter} = create_use_web_module(igniter)

      example_domain = example_domain(options[:user])

      real_example =
        if web_module_exists? do
          """
          # Example of how you might send this email
          # #{inspect(example_domain)}.Emails.send_magic_link_email(
          #   user_or_email,
          #   token
          # )
          """
        end

      url =
        if use_web_module do
          "\#{url(~p\"/magic_link/\#{token}\")}"
        else
          "/auth/user/magic_link/?token=\#{token}"
        end

      Igniter.Project.Module.create_module(
        igniter,
        sender,
        ~s'''
        @moduledoc """
        Sends a magic link email
        """

        use AshAuthentication.Sender
        #{use_web_module}

        @impl true
        def send(user_or_email, token, _) do
          # if you get a user, its for a user that already exists.
          # if you get an email, then the user does not yet exist.
          #{real_example}

          email =
            case user_or_email do
              %{email: email} -> email
              email -> email
            end

          IO.puts("""
          Hello, \#{email}! Click this link to sign in:

          #{url}
          """)
        end
        '''
      )
    end

    defp create_use_web_module(igniter) do
      web_module = Igniter.Libs.Phoenix.web_module(igniter)
      {web_module_exists?, igniter} = Igniter.Project.Module.module_exists(igniter, web_module)

      use_web_module =
        if web_module_exists? do
          "use #{inspect(web_module)}, :verified_routes"
        end

      {web_module_exists?, use_web_module, igniter}
    end

    defp example_domain(user) do
      user |> Module.split() |> :lists.droplast() |> Module.concat()
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.Gen.Stratey.MagicLink do
    @shortdoc "Adds the magic link strategy to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.gen.strategy.magic_link' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
