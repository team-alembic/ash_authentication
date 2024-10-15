defmodule AshAuthentication.Strategy.MagicLink.Request do
  @moduledoc """
  Requests a magic link for the given identity field.
  """
  use Ash.Resource.Actions.Implementation
  alias Ash.{ActionInput, Query}
  alias AshAuthentication.{Info, Strategy.MagicLink}
  # require Ash.Query

  @doc false
  @impl true
  def run(input, _opts, context) do
    strategy = Info.strategy_for_action!(input.resource, input.action.name)

    identity = ActionInput.get_argument(input, strategy.identity_field)

    input.resource
    |> Query.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Ash.Query.for_read(
      strategy.lookup_action_name,
      %{strategy.identity_field => identity},
      Ash.Context.to_opts(context)
    )
    |> Ash.read_one()
    |> case do
      {:error, error} ->
        {:error, error}

      {:ok, nil} ->
        with true <- strategy.registration_enabled?,
             {sender, send_opts} <- strategy.sender,
             {:ok, token} <- MagicLink.request_token_for_identity(strategy, identity) do
          sender.send(to_string(identity), token, send_opts)
        else
          _ ->
            :ok
        end

      {:ok, user} ->
        with {sender, send_opts} <- strategy.sender,
             {:ok, token} <- MagicLink.request_token_for_identity(strategy, identity) do
          sender.send(user, token, send_opts)
        else
          _ ->
            :ok
        end
    end
  end
end
