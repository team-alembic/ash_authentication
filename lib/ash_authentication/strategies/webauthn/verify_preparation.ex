# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.VerifyPreparation do
  @moduledoc """
  Prepare a query for WebAuthn second-factor verification.

  Resolves the user proved by the verify ceremony — see
  `AshAuthentication.Strategy.WebAuthn.CeremonyUser` — and stamps the
  `webauthn_verified_at` metadata the action declares. Assertion verification
  and token generation happen in the Actions module.
  """
  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.Strategy.WebAuthn.CeremonyUser

  @doc false
  @impl Ash.Resource.Preparation
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _options, _context) do
    query
    |> CeremonyUser.constrain("WebAuthn verification runs through the verify ceremony.")
    |> Query.after_action(fn query, users ->
      verified_at = query.context[:private][:webauthn_verified_at]
      {:ok, Enum.map(users, &Ash.Resource.put_metadata(&1, :webauthn_verified_at, verified_at))}
    end)
  end
end
