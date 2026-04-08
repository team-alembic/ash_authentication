defmodule AshAuthentication.SHA256Provider do
  @moduledoc """
  Provides an implementation of `AshAuthentication.HashProvider` using SHA-256.

  This is a fast, deterministic hash provider suitable for hashing high-entropy
  system-generated values like recovery codes. It is NOT suitable for hashing
  user-chosen passwords — use `AshAuthentication.BcryptProvider` or
  `AshAuthentication.Argon2Provider` for passwords.

  Because SHA-256 is fast, inputs must have sufficient entropy to resist offline
  brute-force attacks. This provider requires a minimum of 60 bits of input
  entropy (enforced at compile time by the strategy verifier).
  """
  @behaviour AshAuthentication.HashProvider

  @impl true
  @spec hash(String.t()) :: {:ok, String.t()} | :error
  def hash(input) when is_binary(input) do
    {:ok, :crypto.hash(:sha256, input) |> Base.encode16(case: :lower)}
  end

  def hash(_), do: :error

  @impl true
  @spec valid?(input :: String.t() | nil, hash :: String.t()) :: boolean()
  def valid?(nil, _hash), do: false

  def valid?(input, hash) when is_binary(input) and is_binary(hash) do
    case hash(input) do
      {:ok, computed} -> Plug.Crypto.secure_compare(computed, hash)
      :error -> false
    end
  end

  @impl true
  @spec simulate :: false
  def simulate do
    :crypto.hash(:sha256, "simulate")
    false
  end

  @impl true
  @spec minimum_entropy() :: non_neg_integer()
  def minimum_entropy, do: 60

  @impl true
  @spec deterministic?() :: boolean()
  def deterministic?, do: true
end
