defmodule AshAuthentication.PasswordReset.RequestPasswordResetPreparation do
  @moduledoc """
  Prepare a query for a password reset request.

  This preparation performs three jobs, one before the query executes and two
  after.

  Firstly, it constraints the query to match the identity field passed to the
  action.

  Secondly, if there is a user returned by the query, then generate a reset
  token and publish a notification.  Always returns an empty result.
  """
  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.{PasswordAuthentication, PasswordReset}
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.context()) :: Query.t()
  def prepare(query, _opts, _context) do
    {:ok, identity_field} =
      PasswordAuthentication.Info.password_authentication_identity_field(query.resource)

    {:ok, {sender, send_opts}} = PasswordReset.Info.sender(query.resource)

    identity = Query.get_argument(query, identity_field)

    query
    |> Query.filter(ref(^identity_field) == ^identity)
    |> Query.after_action(fn
      _query, [user] ->
        case PasswordReset.reset_token_for(user) do
          {:ok, token} -> sender.send(user, token, send_opts)
          _ -> nil
        end

        {:ok, []}

      _, _ ->
        {:ok, []}
    end)
  end
end
