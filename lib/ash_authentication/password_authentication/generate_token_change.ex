defmodule AshAuthentication.PasswordAuthentication.GenerateTokenChange do
  @moduledoc """
  Given a successful registration or sign-in, generate a token.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}
  alias AshAuthentication.{Info, Jwt}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _) do
    changeset
    |> Changeset.after_action(fn _changeset, result ->
      if Info.tokens_enabled?(result.__struct__) do
        {:ok, token, _claims} = Jwt.token_for_record(result)
        {:ok, %{result | __metadata__: Map.put(result.__metadata__, :token, token)}}
      else
        {:ok, result}
      end
    end)
  end
end
