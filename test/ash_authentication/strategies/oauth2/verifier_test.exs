# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.VerifierFixture do
  @moduledoc false

  @doc """
  Builds a user resource which pairs an oauth2 strategy with password
  strategies, so `prevent_hijacking/2` has something to inspect.

  `Spark.Test` collects diagnostics through the process dictionary, and the
  verify hook runs in the parallel checker's process. A resource built at run
  time therefore escapes the collector, so callers splice this at compile time.
  """
  def user_ast(module, domain, token, opts) do
    password_order = Keyword.fetch!(opts, :password_order)
    upsert_identity = Keyword.fetch!(opts, :upsert_identity)
    monitor_fields = Keyword.get(opts, :monitor_fields, [:email])
    confirmation? = Keyword.get(opts, :confirmation?, true)
    prevent_hijacking? = Keyword.get(opts, :prevent_hijacking?, true)
    registration_enabled? = Keyword.get(opts, :registration_enabled?, true)

    quote do
      defmodule unquote(module) do
        @moduledoc false
        use Ash.Resource,
          data_layer: Ash.DataLayer.Ets,
          extensions: [AshAuthentication],
          domain: unquote(domain),
          validate_domain_inclusion?: false

        attributes do
          uuid_primary_key(:id)
          attribute(:email, :ci_string, allow_nil?: false, public?: true)
          attribute(:username, :ci_string, allow_nil?: false, public?: true)
          attribute(:hashed_password, :string, allow_nil?: false, sensitive?: true)
        end

        actions do
          defaults([:read])

          read :sign_in_with_oauth2 do
            argument(:user_info, :map, allow_nil?: false)
            argument(:oauth_tokens, :map, allow_nil?: false)
            prepare(AshAuthentication.Strategy.OAuth2.SignInPreparation)
          end

          create :register_with_oauth2 do
            argument(:user_info, :map, allow_nil?: false)
            argument(:oauth_tokens, :map, allow_nil?: false)
            upsert?(true)
            upsert_identity(unquote(upsert_identity))
            change(AshAuthentication.GenerateTokenChange)

            change(
              {AshAuthentication.Strategy.OAuth2.UserInfoToAttributes,
               fields: [:email, :username]}
            )
          end
        end

        identities do
          identity(:unique_email, [:email], pre_check_with: unquote(domain))
          identity(:unique_username, [:username], pre_check_with: unquote(domain))

          identity(:unique_email_and_username, [:email, :username],
            pre_check_with: unquote(domain)
          )
        end

        authentication do
          tokens do
            enabled?(true)
            token_resource(unquote(token))
            signing_secret("Marty McFly in the past with the Delorean")
            store_all_tokens?(true)
            require_token_presence_for_authentication?(true)
          end

          add_ons do
            if unquote(confirmation?) do
              confirmation :confirm do
                monitor_fields(unquote(monitor_fields))
                require_interaction?(true)
                sender(fn _user, _token, _opts -> :ok end)
              end
            end
          end

          strategies do
            for password_strategy <- unquote(password_order) do
              case password_strategy do
                :email_password ->
                  password :email_password do
                    identity_field(:email)
                    register_action_accept([:username])
                  end

                :username_password ->
                  password :username_password do
                    identity_field(:username)
                    register_action_accept([:email])
                  end
              end
            end

            oauth2 do
              client_id("client id")
              client_secret("client secret")
              redirect_uri("http://localhost/auth")
              base_url("http://localhost")
              authorize_url("http://localhost/authorize")
              token_url("http://localhost/token")
              user_url("http://localhost/user")
              prevent_hijacking?(unquote(prevent_hijacking?))
              registration_enabled?(unquote(registration_enabled?))
              warn_on_missing_identity_resource?(false)
            end
          end
        end
      end
    end
  end
end

defmodule AshAuthentication.Strategy.OAuth2.VerifierTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Spark.Test

  alias AshAuthentication.Strategy.OAuth2.VerifierFixture

  defmodule Domain do
    @moduledoc false
    use Ash.Domain, validate_config_inclusion?: false

    resources do
      allow_unregistered? true
    end
  end

  defmodule Token do
    @moduledoc false
    use Ash.Resource,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAuthentication.TokenResource],
      domain: AshAuthentication.Strategy.OAuth2.VerifierTest.Domain

    token do
      domain AshAuthentication.Strategy.OAuth2.VerifierTest.Domain
    end
  end

  @hijack_warning "registers users by upserting on"

  # Matches both this diagnostic and the one it replaced, so a `refute` also
  # catches a spurious complaint from the previous single-candidate check.
  @any_hijack_diagnostic "confirmation tutorial on hexdocs"

  # `AshAuthentication.Info.authentication_strategies/1` returns strategies in
  # reverse declaration order, so every case runs in both orders.
  @orders [
    email_first: [:email_password, :username_password],
    username_first: [:username_password, :email_password]
  ]

  @cases [
    every_unmonitored_field: [
      upsert_identity: :unique_email_and_username,
      monitor_fields: [:email]
    ],
    nothing_monitored: [upsert_identity: :unique_username, monitor_fields: [:email]],
    no_confirmation: [upsert_identity: :unique_email, confirmation?: false],
    all_monitored: [
      upsert_identity: :unique_email_and_username,
      monitor_fields: [:email, :username]
    ],
    uncovered_password_strategy: [upsert_identity: :unique_email, monitor_fields: [:email]],
    hijacking_allowed: [
      upsert_identity: :unique_username,
      monitor_fields: [:email],
      prevent_hijacking?: false
    ],
    registration_disabled: [
      upsert_identity: :unique_username,
      monitor_fields: [:email],
      registration_enabled?: false
    ],
    no_registering_password_strategy: [
      upsert_identity: :unique_username,
      monitor_fields: [:email]
    ]
  ]

  # The check emits a warning, but the version it replaced emitted an error
  # which Spark downgrades to a warning. Both channels are collected so a
  # `refute` cannot pass merely because the diagnostic took the other one.
  for {order_name, order} <- @orders ++ [no_password_strategy: []],
      {case_name, case_opts} <- @cases,
      # The no-password-strategy case does not vary by declaration order.
      case_name == :no_registering_password_strategy == (order_name == :no_password_strategy) do
    opts = Keyword.merge(case_opts, password_order: order)

    base =
      Module.concat([
        AshAuthentication.Strategy.OAuth2.VerifierTest.Resources,
        Macro.camelize("#{case_name}_#{order_name}")
      ])

    warn_ast =
      VerifierFixture.user_ast(
        Module.concat(base, Warn),
        AshAuthentication.Strategy.OAuth2.VerifierTest.Domain,
        AshAuthentication.Strategy.OAuth2.VerifierTest.Token,
        opts
      )

    error_ast =
      VerifierFixture.user_ast(
        Module.concat(base, Error),
        AshAuthentication.Strategy.OAuth2.VerifierTest.Domain,
        AshAuthentication.Strategy.OAuth2.VerifierTest.Token,
        opts
      )

    def diagnostics(unquote(case_name), unquote(order_name)) do
      warnings =
        dsl_warnings do
          unquote(warn_ast)
        end

      errors =
        dsl_errors do
          unquote(error_ast)
        end

      messages =
        Enum.flat_map(warnings, fn {_module, payloads} ->
          Enum.map(payloads, fn {message, _location} -> message end)
        end) ++
          Enum.flat_map(errors, fn {_module, collected} -> Enum.map(collected, & &1.message) end)

      Enum.join(messages, "\n")
    end
  end

  describe "prevent_hijacking/2" do
    for {order_name, _order} <- @orders do
      test "reports every unmonitored field of the upsert identity (#{order_name})" do
        diagnostics = diagnostics(:every_unmonitored_field, unquote(order_name))

        assert diagnostics =~ @hijack_warning
        assert diagnostics =~ "`:unique_email_and_username`"
        assert diagnostics =~ "Unmonitored fields: `:username`."

        assert diagnostics =~
                 "Password strategies which also register users: `:email_password`, `:username_password`."
      end

      test "warns when the upsert identity is not monitored at all (#{order_name})" do
        diagnostics = diagnostics(:nothing_monitored, unquote(order_name))

        assert diagnostics =~ @hijack_warning
        assert diagnostics =~ "Unmonitored fields: `:username`."
      end

      test "warns when there is no confirmation add-on (#{order_name})" do
        diagnostics = diagnostics(:no_confirmation, unquote(order_name))

        assert diagnostics =~ @hijack_warning
        assert diagnostics =~ "Unmonitored fields: `:email`."
      end

      test "stays silent when every upsert field is monitored (#{order_name})" do
        refute diagnostics(:all_monitored, unquote(order_name)) =~ @any_hijack_diagnostic
      end

      test "stays silent when the uncovered password strategy cannot collide with the upsert (#{order_name})" do
        refute diagnostics(:uncovered_password_strategy, unquote(order_name)) =~
                 @any_hijack_diagnostic
      end

      test "stays silent when `prevent_hijacking?` is disabled (#{order_name})" do
        refute diagnostics(:hijacking_allowed, unquote(order_name)) =~ @any_hijack_diagnostic
      end

      test "stays silent when registration is disabled (#{order_name})" do
        refute diagnostics(:registration_disabled, unquote(order_name)) =~ @any_hijack_diagnostic
      end
    end

    test "stays silent when no password strategy registers users" do
      refute diagnostics(:no_registering_password_strategy, :no_password_strategy) =~
               @any_hijack_diagnostic
    end
  end
end
