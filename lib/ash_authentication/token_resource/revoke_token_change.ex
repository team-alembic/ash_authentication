# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.TokenResource.RevokeTokenChange do
  @moduledoc """
  Generates a revocation record for a given token.

  This change does not verify the token.  The token resource holds no signing
  configuration.  It also cannot tell which authentication resource minted the
  token.  `AshAuthentication.Jwt.verify/4` is therefore not available here.
  The caller must verify the token before it runs this action.  See
  `AshAuthentication.TokenResource.Actions.revoke/3`.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Error.Changes.InvalidArgument, Resource.Change}
  alias AshAuthentication.Jwt

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    with token when byte_size(token) > 0 <- Changeset.get_argument(changeset, :token),
         {:ok, %{"jti" => jti, "exp" => exp, "sub" => subject}}
         when is_binary(jti) and byte_size(jti) > 0 and is_integer(exp) and is_binary(subject) <-
           Jwt.peek(token),
         {:ok, expires_at} <- DateTime.from_unix(exp) do
      changeset
      |> Changeset.change_attributes(
        jti: jti,
        purpose: "revocation",
        expires_at: expires_at,
        subject: subject
      )
    else
      _ ->
        changeset
        |> Changeset.add_error([
          InvalidArgument.exception(field: :token, message: "is not a valid token")
        ])
    end
  end
end
