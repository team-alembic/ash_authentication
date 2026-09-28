# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.CeremonyUser do
  @moduledoc """
  Resolves the user of a WebAuthn read action from the ceremony that ran it.

  A WebAuthn assertion can only be checked against a challenge the server
  issued, and that challenge lives outside the action — in the session, or in
  a LiveView's state — so the ceremony runs in
  `AshAuthentication.Strategy.WebAuthn.Actions`, which then runs the action
  with the user it proved in the query's private context. A query without
  that context resolves no user and fails, so the action proves nothing when
  called any other way.
  """

  alias Ash.Query
  alias Ash.Resource.Info, as: ResourceInfo
  alias AshAuthentication.Errors.AuthenticationFailed
  require Ash.Query

  @context_key :webauthn_ceremony_user

  @doc false
  @spec context_key :: atom
  def context_key, do: @context_key

  @doc """
  Constrain `query` to the user proved by the ceremony, or fail it.
  """
  @spec constrain(Query.t(), String.t()) :: Query.t()
  def constrain(query, refusal) do
    case query.context do
      %{private: %{@context_key => %{} = user}} ->
        primary_key =
          user
          |> Map.take(ResourceInfo.primary_key(query.resource))
          |> Enum.to_list()

        Query.filter(query, ^primary_key)

      _ ->
        query
        |> Query.filter(false)
        |> Query.add_error(
          AuthenticationFailed.exception(
            query: query,
            caused_by: %{module: __MODULE__, message: refusal}
          )
        )
    end
  end
end
