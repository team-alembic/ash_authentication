# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.Request do
  @moduledoc """
  Implementation of the OTP request action.

  Looks up the user via the configured `lookup_action_name`, generates an OTP
  code, stores an internal JWT keyed by a deterministic JTI, and dispatches the
  code via the configured sender. Always returns `:ok` so user enumeration is
  not possible from the response. The audit-log status override is set so that
  failed lookups (and senders) are recorded as `:failure`.
  """
  use Ash.Resource.Actions.Implementation
  alias Ash.{ActionInput, Query}
  alias AshAuthentication.{AddOn.AuditLog.Auditor, Errors.SenderFailed, Info, Strategy.Otp}
  require Ash.Query
  import Ash.Expr

  @doc false
  @impl true
  def run(input, _opts, context) do
    strategy = Info.strategy_for_action!(input.resource, input.action.name)
    identity = ActionInput.get_argument(input, strategy.identity_field)
    context_opts = Ash.Context.to_opts(context)

    input.resource
    |> Query.new()
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> Query.for_read(
      strategy.lookup_action_name,
      %{strategy.identity_field => identity},
      context_opts
    )
    |> Query.filter(^ref(strategy.identity_field) == ^identity)
    |> Ash.read_one()
    |> case do
      {:error, error} ->
        {:error, error}

      {:ok, nil} ->
        handle_unknown_identity(input, strategy, identity, context_opts, context)

      {:ok, user} ->
        handle_known_user(input, strategy, user, context_opts, context)
    end
  end

  defp handle_known_user(input, strategy, user, context_opts, context) do
    otp_code = generate_code(strategy)

    token_result =
      if strategy.registration_enabled? do
        identity = Map.get(user, strategy.identity_field)

        Otp.generate_otp_token_for_identity(
          strategy,
          identity,
          otp_code,
          context_opts,
          context
        )
      else
        Otp.generate_otp_token_for(strategy, user, otp_code, context_opts, context)
      end

    case token_result do
      {:ok, _token} ->
        deliver(input, strategy, user, otp_code, context)

      _ ->
        Auditor.record_status_override(input, :failure)
        :ok
    end
  end

  defp handle_unknown_identity(
         input,
         %{registration_enabled?: true} = strategy,
         identity,
         context_opts,
         context
       )
       when not is_nil(identity) do
    otp_code = generate_code(strategy)

    case Otp.generate_otp_token_for_identity(
           strategy,
           identity,
           otp_code,
           context_opts,
           context
         ) do
      {:ok, _token} ->
        deliver(input, strategy, to_string(identity), otp_code, context)

      _ ->
        Auditor.record_status_override(input, :failure)
        :ok
    end
  end

  defp handle_unknown_identity(input, _strategy, _identity, _context_opts, _context) do
    Auditor.record_status_override(input, :failure)
    :ok
  end

  defp deliver(input, strategy, recipient, otp_code, context) do
    {sender, send_opts} = strategy.sender

    build_opts =
      Keyword.merge(send_opts,
        tenant: context.tenant,
        source_context: context.source_context
      )

    case sender.send(recipient, otp_code, build_opts) do
      {:error, reason} when not is_struct(reason) ->
        Auditor.record_status_override(input, :failure)

        {:error, SenderFailed.exception(sender: sender, reason: reason, strategy: strategy.name)}

      {:error, _} = error ->
        Auditor.record_status_override(input, :failure)
        error

      _ ->
        Auditor.record_status_override(input, :success)
        :ok
    end
  end

  defp generate_code(strategy) do
    generator = strategy.otp_generator || Otp.DefaultGenerator

    generator.generate(
      length: strategy.otp_length,
      characters: strategy.otp_characters
    )
  end
end
