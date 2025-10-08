# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.LogOutEverywhere.Action do
  @moduledoc """
  Revokes all tokens for the specified user.
  """
  use Ash.Resource.Actions.Implementation

  alias Ash.Error.Framework.AssumptionFailed
  alias AshAuthentication.Info

  alias AshAuthentication.TokenResource.Info, as: TokenResourceInfo
  require Ash.Query

  @doc false
  @impl true
  def run(input, _opts, context) do
    case Info.strategy_for_action(input.resource, input.action.name) do
      {:ok, strategy} ->
        really_run_action(input, strategy, context)

      :error ->
        raise AssumptionFailed,
          message: "Action does not correlate with an authentication strategy"
    end
  end

  defp really_run_action(input, strategy, context) do
    user = Map.fetch!(input.arguments, strategy.argument_name)
    subject = AshAuthentication.user_to_subject(user)
    revoke_all_tokens_for_subject(subject, strategy, context)
  end

  defp revoke_all_tokens_for_subject(subject, strategy, context) do
    with {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource),
         {:ok, revoke_all_tokens_action_name} <-
           TokenResourceInfo.token_revocation_revoke_all_stored_for_subject_action_name(
             token_resource
           ) do
      token_resource
      |> include_purposes(strategy)
      |> exclude_purposes(strategy)
      |> Ash.bulk_update(
        revoke_all_tokens_action_name,
        %{subject: subject},
        Ash.Context.to_opts(context,
          strategy: [:atomic, :atomic_batches, :stream],
          context: %{private: %{ash_authentication?: true}},
          return_errors?: true,
          stop_on_error?: true
        )
      )
      |> case do
        %{status: :success} ->
          :ok

        %{errors: errors} ->
          {:error, errors}
      end
    end
  end

  defp include_purposes(query, strategy) do
    if strategy.include_purposes do
      Ash.Query.filter(query, purpose in ^strategy.include_purposes)
    else
      query
    end
  end

  defp exclude_purposes(query, strategy) do
    if strategy.exclude_purposes do
      Ash.Query.filter(query, purpose not in ^strategy.exclude_purposes)
    else
      query
    end
  end
end
