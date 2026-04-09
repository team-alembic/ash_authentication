# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

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

    case Ash.Changeset.fetch_argument(changeset, :recovery_codes) do
      {:ok, plaintext_codes} when is_list(plaintext_codes) ->
        hashed_codes =
          Enum.map(plaintext_codes, fn code ->
            {:ok, hashed} = hash_provider.hash(code)
            hashed
          end)

        changeset
        |> Ash.Changeset.set_argument(:recovery_codes, hashed_codes)
        |> Ash.Changeset.after_action(fn _changeset, user ->
          {:ok, Ash.Resource.put_metadata(user, :recovery_codes, plaintext_codes)}
        end)

      _ ->
        changeset
    end
  end
end
