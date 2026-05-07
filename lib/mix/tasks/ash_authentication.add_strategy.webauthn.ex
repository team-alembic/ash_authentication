# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Webauthn do
    use Igniter.Mix.Task

    @example "mix ash_authentication.add_strategy.webauthn"

    @shortdoc "Adds WebAuthn/Passkey authentication to your user resource"

    @moduledoc """
    #{@shortdoc}

    Creates a credential resource and adds the WebAuthn strategy to the user
    resource. Users can sign in with hardware security keys (YubiKey),
    platform authenticators (Touch ID, Windows Hello), or passkeys.

    `rp_id`, `rp_name`, and `origin` are wired through your generated
    `Secrets` module and read from the application environment, so you can
    configure them per-environment via `config/dev.exs`, `config/test.exs`,
    and `config/runtime.exs` (which is seeded with `System.get_env/1` reads
    of `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, and `WEBAUTHN_ORIGIN`).

    ## Example

    ```bash
    #{@example}
    ```

    ## Options

    * `--user`, `-u` - The user resource. Defaults to `YourApp.Accounts.User`.
    * `--identity-field`, `-i` - The field on the user resource that
      identifies the user (typically email). Defaults to `email`.
    * `--name`, `-n` - The strategy name. Defaults to `webauthn`.
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
          identity_field: :string,
          name: :string
        ],
        aliases: [
          a: :accounts,
          u: :user,
          i: :identity_field,
          n: :name
        ],
        defaults: [
          identity_field: "email",
          name: "webauthn"
        ]
      }
    end

    def igniter(igniter) do
      options = parse_options(igniter)
      secrets_module = Igniter.Project.Module.module_name(igniter, "Secrets")

      case Igniter.Project.Module.module_exists(igniter, options[:user]) do
        {true, igniter} ->
          igniter
          |> add_wax_dependency()
          |> add_credential_resource(secrets_module, options)
          |> add_webauthn_secrets(secrets_module, options)
          |> AshAuthentication.Igniter.codegen_for_strategy(options[:name])

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
      |> Keyword.update(:name, :webauthn, &String.to_atom/1)
      |> Keyword.update!(:accounts, &AshAuthentication.Igniter.maybe_parse_module/1)
      |> Keyword.update!(:user, &AshAuthentication.Igniter.maybe_parse_module/1)
    end

    defp add_wax_dependency(igniter) do
      Igniter.Project.Deps.add_dep(igniter, {:wax_, "~> 0.7"}, on_exists: :skip)
    end

    defp add_credential_resource(igniter, secrets_module, options) do
      credential_resource =
        options[:user]
        |> Module.split()
        |> :lists.droplast()
        |> Enum.concat([WebAuthnCredential])
        |> Module.concat()

      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, credential_resource)

      if exists? do
        Igniter.add_issue(
          igniter,
          "WebAuthn credential resource already exists: #{inspect(credential_resource)}."
        )
      else
        igniter
        |> generate_credential_resource(credential_resource, options)
        |> add_user_attributes_and_relationship(credential_resource, options)
        |> add_strategy_to_user(credential_resource, secrets_module, options)
      end
    end

    defp generate_credential_resource(igniter, credential_resource, options) do
      extensions = data_layer_extension()

      igniter
      |> Igniter.compose_task("ash.gen.resource", [
        inspect(credential_resource),
        "--uuid-primary-key",
        "id",
        "--default-actions",
        "read,destroy",
        "--attribute",
        "credential_id:binary:required",
        "--attribute",
        "sign_count:integer",
        "--attribute",
        "label:string",
        "--attribute",
        "last_used_at:utc_datetime_usec",
        "--relationship",
        "belongs_to:user:#{inspect(options[:user])}:required",
        "--extend",
        extensions
      ])
      |> Ash.Resource.Igniter.add_new_attribute(credential_resource, :public_key, """
      attribute :public_key, AshAuthentication.Strategy.WebAuthn.CoseKey do
        allow_nil? false
        public? true
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(credential_resource, :create, """
      create :create do
        primary? true
        accept [:credential_id, :public_key, :sign_count, :label, :user_id]
      end
      """)
      |> Ash.Resource.Igniter.add_new_action(credential_resource, :update, """
      update :update do
        primary? true
        accept [:sign_count, :label, :last_used_at]
      end
      """)
      |> add_credential_resource_authorizer(credential_resource)
      |> Ash.Resource.Igniter.add_new_identity(credential_resource, :unique_credential_id, """
      identity :unique_credential_id, [:credential_id]
      """)
    end

    defp add_credential_resource_authorizer(igniter, credential_resource) do
      Igniter.Project.Module.find_and_update_module!(
        igniter,
        credential_resource,
        &ensure_authorizer_bypass/1
      )
    end

    defp ensure_authorizer_bypass(zipper) do
      with {:ok, do_zipper} <- Igniter.Code.Common.move_to_do_block(zipper),
           :error <-
             Igniter.Code.Function.move_to_function_call_in_current_scope(
               do_zipper,
               :policies,
               1
             ) do
        {:ok,
         Igniter.Code.Common.add_code(do_zipper, """
         policies do
           bypass AshAuthentication.Checks.AshAuthenticationInteraction do
             authorize_if always()
           end
         end
         """)}
      else
        {:ok, _} -> {:ok, zipper}
        :error -> {:ok, zipper}
      end
    end

    defp add_user_attributes_and_relationship(igniter, credential_resource, options) do
      identity_field = options[:identity_field]

      igniter
      |> Ash.Resource.Igniter.add_new_attribute(options[:user], identity_field, """
      attribute #{inspect(identity_field)}, :ci_string do
        allow_nil? false
        public? true
      end
      """)
      |> make_hashed_password_optional(options)
      |> AshAuthentication.Igniter.ensure_identity(options[:user], identity_field)
      |> Ash.Resource.Igniter.add_new_relationship(
        options[:user],
        :webauthn_credentials,
        """
        has_many :webauthn_credentials, #{inspect(credential_resource)}
        """
      )
    end

    # WebAuthn registration creates users without a password. If the password
    # strategy is also installed, its `hashed_password` attribute is generated
    # with `allow_nil? false`, which conflicts with the WebAuthn register flow.
    # Drop the `allow_nil? false` line so both strategies can coexist on the
    # same resource. No-op if the attribute (or that line) isn't present.
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
          _ -> {:ok, zipper}
        end
      end)
    end

    defp add_strategy_to_user(igniter, credential_resource, secrets_module, options) do
      AshAuthentication.Igniter.add_new_strategy(
        igniter,
        options[:user],
        options[:name],
        options[:name],
        strategy_block(credential_resource, secrets_module, options)
      )
    end

    defp strategy_block(credential_resource, secrets_module, options) do
      """
      webauthn #{inspect(options[:name])} do
        credential_resource #{inspect(credential_resource)}
        rp_id #{inspect(secrets_module)}
        rp_name #{inspect(secrets_module)}
        origin #{inspect(secrets_module)}
        identity_field #{inspect(options[:identity_field])}
      end
      """
    end

    defp add_webauthn_secrets(igniter, secrets_module, options) do
      otp_app = Igniter.Project.Application.app_name(igniter)
      strategy_name = options[:name]
      rp_name_default = humanise_app_name(otp_app)

      igniter
      |> AshAuthentication.Igniter.add_new_secret_from_env(
        secrets_module,
        options[:user],
        [:authentication, :strategies, strategy_name, :rp_id],
        :webauthn_rp_id
      )
      |> AshAuthentication.Igniter.add_new_secret_from_env(
        secrets_module,
        options[:user],
        [:authentication, :strategies, strategy_name, :rp_name],
        :webauthn_rp_name
      )
      |> AshAuthentication.Igniter.add_new_secret_from_env(
        secrets_module,
        options[:user],
        [:authentication, :strategies, strategy_name, :origin],
        :webauthn_origin
      )
      |> Igniter.Project.Config.configure_new(
        "dev.exs",
        otp_app,
        [:webauthn_rp_id],
        "localhost"
      )
      |> Igniter.Project.Config.configure_new(
        "dev.exs",
        otp_app,
        [:webauthn_rp_name],
        rp_name_default
      )
      |> Igniter.Project.Config.configure_new(
        "test.exs",
        otp_app,
        [:webauthn_rp_id],
        "localhost"
      )
      |> Igniter.Project.Config.configure_new(
        "test.exs",
        otp_app,
        [:webauthn_rp_name],
        rp_name_default
      )
      |> Igniter.Project.Config.configure_runtime_env(
        :prod,
        otp_app,
        [:webauthn_rp_id],
        runtime_env_value("WEBAUTHN_RP_ID")
      )
      |> Igniter.Project.Config.configure_runtime_env(
        :prod,
        otp_app,
        [:webauthn_rp_name],
        runtime_env_value("WEBAUTHN_RP_NAME")
      )
      |> Igniter.Project.Config.configure_runtime_env(
        :prod,
        otp_app,
        [:webauthn_origin],
        runtime_env_value("WEBAUTHN_ORIGIN")
      )
    end

    defp runtime_env_value(env_var) do
      {:code, Sourceror.parse_string!(~s|System.get_env("#{env_var}")|)}
    end

    defp humanise_app_name(otp_app) do
      otp_app
      |> Atom.to_string()
      |> String.split("_")
      |> Enum.map_join(" ", &String.capitalize/1)
    end

    defp data_layer_extension do
      cond do
        Code.ensure_loaded?(AshPostgres.DataLayer) -> "Ash.Policy.Authorizer,postgres"
        Code.ensure_loaded?(AshSqlite.DataLayer) -> "Ash.Policy.Authorizer,sqlite"
        true -> "Ash.Policy.Authorizer"
      end
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.AddStrategy.Webauthn do
    @shortdoc "Adds WebAuthn/Passkey authentication to your user resource"

    @moduledoc @shortdoc

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.add_strategy.webauthn' requires igniter to be run.

      Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter
      """)

      exit({:shutdown, 1})
    end
  end
end
