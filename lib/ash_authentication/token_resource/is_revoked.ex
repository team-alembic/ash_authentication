# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.TokenResource.IsRevoked do
  @moduledoc """
  Checks for the existence of a revocation token for the provided token revocation token for the provided token.
  """
  use Ash.Resource.Actions.Implementation
  alias Ash.Error.Action.InvalidArgument
  alias AshAuthentication.{Errors.InvalidToken, Jwt}

  @impl true
  def run(%{resource: resource, arguments: %{jti: jti}}, _, context) when is_binary(jti) do
    resource
    |> Ash.Query.do_filter(purpose: "revocation", jti: jti)
    |> Ash.Query.set_context(%{
      private: %{ash_authentication?: true}
    })
    |> Ash.Query.set_tenant(context.tenant)
    |> Ash.exists()
  end

  def run(%{arguments: %{token: token}} = input, opts, context) when is_binary(token) do
    case Jwt.peek(token) do
      {:ok, %{"jti" => jti}} -> run(%{input | arguments: %{jti: jti}}, opts, context)
      {:ok, _} -> {:error, InvalidToken.exception(type: :revocation)}
      {:error, reason} -> {:error, reason}
    end
  end

  def run(_input, _, _) do
    {:error,
     InvalidArgument.exception(
       field: :jti,
       message: "At least one of `jti` or `token` arguments must be present"
     )}
  end
end
