# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Otp do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy.otp"

    @shortdoc "Adds one-time password (OTP) authentication to your user resource"

    @moduledoc """
    #{@shortdoc}

    Adds the OTP strategy to your user resource — passwordless authentication
    via a short code (e.g. `XKPTMH`) sent via email or SMS.

    Brute-force protection is required by the strategy. By default this task
    composes an `audit_log` add-on (creating one if it doesn't already exist)
    and wires `brute_force_strategy {:audit_log, :audit_log}` into the
    strategy.

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` - The user resource. Defaults to `YourApp.Accounts.User`
    * `--identity-field`, `-i` - The field on the user resource that will be
      used to identify the user. Defaults to `email`
    * `--name`, `-n` - The name of the OTP strategy. Defaults to `otp`.

    ## Notes

    `registration_enabled?: true` (sign-in becomes an upsert) is not currently
    supported by this task because the verifier forbids the `:audit_log`
    brute-force strategy in registration mode, and the alternatives
    (`:rate_limit` or `{:preparation, ...}`) require user-supplied
    configuration. Add the strategy by hand and follow the OTP tutorial if you
    need that mode.
    """

    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :ash,
        example: @example,
        extra_args?: false,
        only: nil,
        positional: [],
        composes: [
          "ash_authentication.add_add_on.audit_log"
        ],
        schema: [
          accounts: :string,
          user: :string,
          identity_field: :string,
          name: :string,
          registration: :boolean
        ],
        aliases: [
          a: :accounts,
          u: :user,
          i: :identity_field,
          n: :name
        ],
        defaults: [
          identity_field: "email",
          name: "otp"
        ]
      }
    end

    def igniter(igniter) do
      options = parse_options(igniter)

      if options[:registration] do
        Mix.shell().error("""
        `--registration` is not supported by this task.

        When `registration_enabled?` is true, the OTP strategy cannot use the
        `:audit_log` brute-force strategy (the verifier rejects it). The
        alternatives are `:rate_limit` (requires the AshRateLimiter extension
        and a backend) or `{:preparation, MyMod}` (requires you to write a
        preparation module). Both need decisions this generator can't make
        safely on your behalf.

        Add the OTP strategy by hand and follow the OTP tutorial:
        https://hexdocs.pm/ash_authentication/otp.html
        """)

        exit({:shutdown, 1})
      end

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          igniter
          |> otp(options)
          |> AshAuthentication.Igniter.codegen_for_strategy(:otp)

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
      |> Keyword.update(:name, :otp, &String.to_atom/1)
      |> Keyword.update!(:accounts, &AshAuthentication.Igniter.maybe_parse_module/1)
      |> Keyword.update!(:user, &AshAuthentication.Igniter.maybe_parse_module/1)
    end

    # sobelow_skip ["DOS.BinToAtom"]
    defp otp(igniter, options) do
      sender = Module.concat(options[:user], Senders.SendOtp)
      strategy_name = options[:name]
      identity_field = options[:identity_field]
      request_action = :"request_#{strategy_name}"
      sign_in_action = :"sign_in_with_#{strategy_name}"

      igniter
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], identity_field, """
      attribute #{inspect(identity_field)}, :ci_string do
        allow_nil? false
        public? true
      end
      """)
      |> AshAuthentication.Igniter.ensure_identity(options[:user], identity_field)
      |> AshAuthentication.Igniter.ensure_get_by_action(options[:user], identity_field)
      |> compose_audit_log(options)
      |> Ash.Resource.Igniter.add_new_action(options[:user], request_action, """
      action #{inspect(request_action)} do
        argument #{inspect(identity_field)}, :ci_string do
          allow_nil? false
          description "The identity to send a one-time password to."
        end

        run AshAuthentication.Strategy.Otp.Request
        description "Send a one-time password to a user if they exist."
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(options[:user], sign_in_action, """
      read #{inspect(sign_in_action)} do
        description "Sign in a user with a one-time password."
        get? true

        argument #{inspect(identity_field)}, :ci_string do
          allow_nil? false
        end

        argument :otp, :string do
          allow_nil? false
          sensitive? true
        end

        prepare AshAuthentication.Strategy.Otp.SignInPreparation

        metadata :token, :string do
          allow_nil? false
        end
      end
      """)
      |> AshAuthentication.Igniter.add_new_strategy(
        options[:user],
        :otp,
        strategy_name,
        """
        otp #{inspect(strategy_name)} do
          identity_field #{inspect(identity_field)}
          brute_force_strategy {:audit_log, :audit_log}
          sender #{inspect(sender)}
        end
        """
      )
      |> create_new_otp_sender(sender, options)
    end

    defp compose_audit_log(igniter, options) do
      {igniter, has_audit_log?} =
        AshAuthentication.Igniter.defines_add_on(igniter, options[:user], :audit_log, nil)

      if has_audit_log? do
        igniter
      else
        Igniter.compose_task(
          igniter,
          "ash_authentication.add_add_on.audit_log",
          ["--user", inspect(options[:user])]
        )
      end
    end

    defp create_new_otp_sender(igniter, sender, _options) do
      Igniter.Project.Module.create_module(
        igniter,
        sender,
        ~s'''
        @moduledoc """
        Sends a one-time password code to the user.
        """

        use AshAuthentication.Sender

        @impl true
        def send(user, otp_code, _opts) do
          # The `user` argument is the user record matching the identity that
          # was submitted. The `otp_code` is the short code that should be
          # sent to them — typically by email or SMS.

          IO.puts("""
          Hello, \#{user.email}! Your sign-in code is:

              \#{otp_code}

          This code expires in 10 minutes.
          """)
        end
        ''',
        on_exists: :warning
      )
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Otp do
    @shortdoc "Adds one-time password (OTP) authentication to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_strategy.otp' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
