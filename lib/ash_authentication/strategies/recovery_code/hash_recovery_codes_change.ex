defmodule AshAuthentication.Strategy.RecoveryCode.HashRecoveryCodesChange do
  @moduledoc """
  Change that hashes recovery codes before storage.

  Reads plaintext codes from the `:recovery_codes` argument, hashes them
  using the configured hash provider, and replaces the argument with
  hashed values. The plaintext codes are returned via action metadata.
  """
  use Ash.Resource.Change

  @impl true
  def init(opts) do
    {:ok, opts}
  end

  @impl true
  def change(changeset, opts, _context) do
    hash_provider = opts[:hash_provider]
    use_shared_salt? = opts[:use_shared_salt?]

    salt =
      if use_shared_salt? do
        hash_provider.gen_salt()
      end

    case Ash.Changeset.fetch_argument(changeset, :recovery_codes) do
      {:ok, plaintext_codes} when is_list(plaintext_codes) ->
        hashed_codes = Enum.map(plaintext_codes, &hash_code(&1, hash_provider, salt))

        changeset
        |> Ash.Changeset.set_argument(:recovery_codes, hashed_codes)
        |> Ash.Changeset.after_action(fn _changeset, user ->
          {:ok, Ash.Resource.put_metadata(user, :recovery_codes, plaintext_codes)}
        end)

      _ ->
        changeset
    end
  end

  defp hash_code(code, hash_provider, nil), do: elem(hash_provider.hash(code), 1)

  defp hash_code(code, hash_provider, salt), do: elem(hash_provider.hash(code, salt), 1)
end
