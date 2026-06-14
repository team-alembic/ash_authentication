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
  alias AshAuthentication.Info
  require Ash.Query

  @doc false
  @impl Ash.Resource.Preparation
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, options, context) do
    with {:ok,
          %_{
            identity_field: identity_field,
            require_identity?: true
          }} <- Info.find_strategy(query, context, options) do
      case Query.get_argument(query, identity_field) do
        nil -> Query.filter(query, false)
        identity -> Query.filter(query, ^ref(identity_field) == ^identity)
      end
    else
      _ -> query
    end
  end
end
