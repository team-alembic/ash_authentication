defmodule AshAuthentication.TokenResource.RevokeJtiChange do
  @moduledoc """
  Generates a revocation record for a given token.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    jti = changeset.arguments.jti
    subject = changeset.arguments.subject

    changeset
    |> Changeset.change_attributes(
      jti: jti,
      purpose: "revocation",
      expires_at: DateTime.shift(DateTime.utc_now(), year: 1000),
      subject: subject
    )
  end
end
