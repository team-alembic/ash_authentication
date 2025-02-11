defmodule AshAuthentication.AddOn.LogOutEverywhere.Action do
  @moduledoc """
  Revokes all tokens for the specified user.
  """
  use Ash.Resource.Actions.Implementation

  alias Ash.{
    ActionInput,
    Error.Framework.AssumptionFailed,
    Query,
    Resource
  }

  alias AshAuthentication.Info

  @doc false
  @impl true
  def run(input, _opts, _context) do
    case Info.strategy_for_action(input.resource, input.action.name) do
      {:ok, strategy} ->
        really_run_action(input, strategy)

      :error ->
        raise AssumptionFailed,
          message: "Action does not correlate with an authentication strategy"
    end
  end

  defp really_run_action(input, strategy) do
    with {:ok, user_id} <- ActionInput.fetch_argument(input, strategy.argument_name),
         {:ok, user} <- get_user_by_id(user_id, strategy) do
      subject = AshAuthentication.user_to_subject(user)
      revoke_all_tokens_for_subject(subject, strategy)
    end
  end

  defp get_user_by_id(user_id, strategy) do
    with [id] <- Resource.Info.primary_key(strategy.resource) do
      strategy.resource
      |> Query.new()
      |> Query.set_context(%{private: %{ash_authentication?: true}})
      |> Query.do_filter([{id, user_id}])
      |> Ash.read_one()
    end
  end

  defp revoke_all_tokens_for_subject(subject, strategy) do
    with {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource),
         {:ok, tokens} <- get_all_tokens_for_subject(token_resource, subject) do
      tokens
      |> Stream.map(
        &%{
          jti: &1.jti,
          purpose: "revocation",
          expires_at: &1.expires_at,
          subject: subject
        }
      )
      |> Ash.bulk_create(token_resource, :create,
        context: %{private: %{ash_authentication?: true}},
        return_errors?: true,
        upsert?: true,
        upsert_fields: [:purpose]
      )
      |> case do
        %{status: :success} -> :ok
        %{errors: errors} -> {:error, errors}
      end
    end
  end

  defp get_all_tokens_for_subject(token_resource, subject) do
    token_resource
    |> Query.new()
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> Query.do_filter(subject: subject)
    |> Query.for_read(:read)
    |> Ash.read()
  end
end
