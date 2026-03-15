# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.RequestPreparation do
  @moduledoc """
  Prepare a query for an OTP request.

  This preparation performs the following:
  1. Constrains the query to match the identity field passed to the action.
  2. If there is a user returned by the query, generates an OTP code, stores
     an internal JWT with a deterministic JTI, and sends the OTP code to the user
     via the configured sender.

  Always returns an empty result (never reveals user existence).
  """
  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.{Info, Strategy.Otp}
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _opts, context) do
    strategy = Info.strategy_for_action!(query.resource, query.action.name)

    identity_field = strategy.identity_field
    identity = Query.get_argument(query, identity_field)
    select_for_senders = Info.authentication_select_for_senders!(query.resource)

    if is_nil(identity) do
      Query.filter(query, false)
    else
      Query.filter(query, ^ref(identity_field) == ^identity)
    end
    |> Query.before_action(fn query ->
      query
      |> Ash.Query.ensure_selected(select_for_senders)
      |> Ash.Query.ensure_selected([identity_field])
    end)
    |> Query.after_action(&after_action(&1, &2, strategy, identity, context))
  end

  defp after_action(_query, [user], strategy, _identity, context) do
    otp_code = generate_code(strategy)
    {sender, send_opts} = strategy.sender
    context_opts = Ash.Context.to_opts(context)

    # When registration is enabled, use identity-based JTI for consistency
    # (same computation in both request and sign-in, regardless of user existence).
    result =
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

    case result do
      {:ok, _token} ->
        sender.send(user, otp_code, Keyword.put(send_opts, :tenant, context.tenant))

      _ ->
        nil
    end

    {:ok, []}
  end

  defp after_action(
         _query,
         _,
         %{registration_enabled?: true, sender: {sender, send_opts}} = strategy,
         identity,
         context
       )
       when not is_nil(identity) do
    otp_code = generate_code(strategy)
    context_opts = Ash.Context.to_opts(context)

    case Otp.generate_otp_token_for_identity(
           strategy,
           identity,
           otp_code,
           context_opts,
           context
         ) do
      {:ok, _token} ->
        sender.send(
          to_string(identity),
          otp_code,
          Keyword.put(send_opts, :tenant, context.tenant)
        )

      _ ->
        nil
    end

    {:ok, []}
  end

  defp after_action(_, _, _, _, _) do
    {:ok, []}
  end

  defp generate_code(strategy) do
    generator = strategy.otp_generator || Otp.DefaultGenerator

    generator.generate(
      length: strategy.otp_length,
      characters: strategy.otp_characters
    )
  end
end
