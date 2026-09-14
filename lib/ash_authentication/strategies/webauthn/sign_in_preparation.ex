# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.SignInPreparation do
  @moduledoc """
  Prepare a query for WebAuthn sign in.

  Constrains the query to match the identity field passed to the action.
  Unlike the Password strategy's SignInPreparation, this module does NOT
  handle credential verification or token generation - those happen in
  the Actions module after Wax assertion verification.
  """
  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.{Errors.AuthenticationFailed, Info}
  require Ash.Query

  @doc false
  @impl Ash.Resource.Preparation
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, options, context) do
    case Info.find_strategy(query, context, options) do
      {:ok, %_{identity_field: identity_field, require_identity?: true}} ->
        case Query.get_argument(query, identity_field) do
          nil -> Query.filter(query, false)
          identity -> Query.filter(query, ^ref(identity_field) == ^identity)
        end

      {:ok, %_{require_identity?: false}} ->
        # Passkey-first mode: the user is resolved from the credential id in
        # `Actions.sign_in/3`, not by this query. Constrain to nothing so a
        # direct read of the sign-in action can never enumerate every user.
        Query.filter(query, false)

      :error ->
        # No strategy resolved for this query: fail closed rather than
        # returning an unfiltered (all-users) query, and surface the failure
        # instead of swallowing it.
        query
        |> Query.filter(false)
        |> Query.add_error(
          AuthenticationFailed.exception(
            query: query,
            caused_by: %{
              module: __MODULE__,
              message: "Unable to identify the WebAuthn strategy for this sign-in query."
            }
          )
        )
    end
  end
end
