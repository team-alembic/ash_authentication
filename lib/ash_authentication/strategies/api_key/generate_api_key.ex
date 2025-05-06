defmodule AshAuthentication.Strategy.ApiKey.GenerateApiKey do
  @moduledoc """
  Generates a random API key for a user.

  The API key is generated using a random byte string and a prefix. The prefix
  is used to generate a key that is compliant with secret scanning. You can use
  this to set up an endpoint that will automatically revoke leaked tokens, which
  is an extremely powerful and useful security feature.

  See [the guide on Github](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partnership-program/secret-scanning-partner-program) for more information.

  ## Options

  * `:prefix` - The prefix to use for the API key.
  """

  use Ash.Resource.Change

  def change(changeset, opts, _) do
    prefix = to_string(Keyword.fetch!(opts, :prefix))

    if String.match?(prefix, ~r/[^a-z0-9]/) do
      raise ArgumentError,
            "#{inspect(prefix)} contains invalid characters. Must contain only `a-z0-9`"
    end

    random_bytes = :crypto.strong_rand_bytes(32)
    id = Ecto.UUID.bingenerate()

    changeset = Ash.Changeset.force_change_attribute(changeset, :id, id)

    api_key =
      "#{prefix}_#{AshAuthentication.Base.encode62(id <> random_bytes)}_#{AshAuthentication.Base.encode62(:erlang.crc32(id <> random_bytes))}"

    hash = :crypto.hash(:sha256, id <> random_bytes)

    changeset
    |> Ash.Changeset.force_change_attribute(opts[:hash], hash)
    |> Ash.Changeset.after_action(fn _changeset, result ->
      {:ok, Ash.Resource.set_metadata(result, %{plaintext_api_key: api_key})}
    end)
  end
end
