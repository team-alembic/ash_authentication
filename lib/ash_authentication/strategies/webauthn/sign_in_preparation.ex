# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.SignInPreparation do
  @moduledoc """
  Prepare a query for WebAuthn sign in.

  Resolves the user proved by the sign-in ceremony — see
  `AshAuthentication.Strategy.WebAuthn.CeremonyUser` — and, when the strategy
  requires an identity, constrains the query to the one passed to the action
  too. Unlike the Password strategy's SignInPreparation, this module does NOT
  handle credential verification or token generation - those happen in
  the Actions module after Wax assertion verification.
  """
  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.{Errors.AuthenticationFailed, Info}
  alias AshAuthentication.Strategy.WebAuthn.CeremonyUser
  require Ash.Query

  @doc false
  @impl Ash.Resource.Preparation
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, options, context) do
    case Info.find_strategy(query, context, options) do
      {:ok, %_{identity_field: identity_field, require_identity?: true}} ->
        query = constrain_to_ceremony_user(query)

        case Query.get_argument(query, identity_field) do
          nil -> Query.filter(query, false)
          identity -> Query.filter(query, ^ref(identity_field) == ^identity)
        end

      {:ok, %_{require_identity?: false}} ->
        # Passkey-first mode: the ceremony resolved the user from the
        # credential id, so that user is the only constraint.
        constrain_to_ceremony_user(query)

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

  defp constrain_to_ceremony_user(query) do
    CeremonyUser.constrain(query, "WebAuthn sign-in runs through the sign-in ceremony.")
  end
end
