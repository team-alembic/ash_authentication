defmodule AshAuthentication.TokenRevocation.RevokeTokenChange do
  @moduledoc """
  Decode the passed in token and build a revocation based on it's claims.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Error.Changes.InvalidArgument, Resource.Change}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _) do
    changeset
    |> Changeset.before_action(fn changeset ->
      changeset
      |> Changeset.get_argument(:token)
      |> Joken.peek_claims()
      |> case do
        {:ok, %{"jti" => jti, "exp" => exp}} ->
          expires_at =
            exp
            |> DateTime.from_unix!()

          changeset
          |> Changeset.change_attributes(jti: jti, expires_at: expires_at)

        {:error, reason} ->
          {:error, InvalidArgument.exception(field: :token, message: to_string(reason))}
      end
    end)
  end
end
