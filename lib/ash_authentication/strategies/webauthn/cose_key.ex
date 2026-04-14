defmodule AshAuthentication.Strategy.WebAuthn.CoseKey do
  @moduledoc """
  An Ash type for storing COSE public keys using CBOR encoding.

  COSE keys are the standard format for WebAuthn credential public keys.
  They are stored as CBOR-encoded binary in the database and decoded to
  Elixir maps at runtime.
  """

  use Ash.Type

  @max_cose_key_size 262_144

  @impl true
  def storage_type(_), do: :binary

  @impl true
  def cast_input(value, _) when is_map(value), do: {:ok, value}

  def cast_input(value, _) when is_binary(value) do
    if byte_size(value) > @max_cose_key_size do
      :error
    else
      case CBOR.decode(value) do
        {:ok, decoded, _} when is_map(decoded) -> {:ok, decoded}
        _ -> :error
      end
    end
  end

  def cast_input(nil, _), do: {:ok, nil}
  def cast_input(_, _), do: :error

  @impl true
  def dump_to_native(value, _) when is_map(value) do
    {:ok, CBOR.encode(value) |> IO.iodata_to_binary()}
  end

  def dump_to_native(nil, _), do: {:ok, nil}
  def dump_to_native(_, _), do: :error

  @impl true
  def cast_stored(value, _) when is_binary(value) do
    case CBOR.decode(value) do
      {:ok, decoded, _} when is_map(decoded) -> {:ok, decoded}
      _ -> :error
    end
  end

  def cast_stored(nil, _), do: {:ok, nil}
  def cast_stored(_, _), do: :error
end
