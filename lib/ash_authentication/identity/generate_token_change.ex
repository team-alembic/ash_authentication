defmodule AshAuthentication.Identity.GenerateTokenChange do
  @moduledoc """
  Given a successful registration, generate a token.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}
  alias AshAuthentication.JsonWebToken

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _) do
    changeset
    |> Changeset.after_action(fn _changeset, result ->
      {:ok, token, _claims} = JsonWebToken.token_for_record(result)
      {:ok, %{result | __metadata__: Map.put(result.__metadata__, :token, token)}}
    end)
  end
end
