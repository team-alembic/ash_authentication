defmodule AshAuthentication.Strategy.WebAuthn.CoseKeyTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.WebAuthn.CoseKey

  @sample_cose_key %{
    1 => 2,
    3 => -7,
    -1 => 1,
    -2 => :crypto.strong_rand_bytes(32),
    -3 => :crypto.strong_rand_bytes(32)
  }

  describe "storage_type/1" do
    test "returns :binary" do
      assert :binary = CoseKey.storage_type([])
    end
  end

  describe "cast_input/2" do
    test "accepts a map" do
      assert {:ok, @sample_cose_key} = CoseKey.cast_input(@sample_cose_key, [])
    end

    test "accepts CBOR binary" do
      cbor = CBOR.encode(@sample_cose_key) |> IO.iodata_to_binary()
      assert {:ok, decoded} = CoseKey.cast_input(cbor, [])
      assert is_map(decoded)
    end

    test "rejects invalid binary" do
      assert :error = CoseKey.cast_input("not-cbor", [])
    end

    test "accepts nil" do
      assert {:ok, nil} = CoseKey.cast_input(nil, [])
    end
  end

  describe "dump_to_native/2" do
    test "encodes map to CBOR binary" do
      assert {:ok, binary} = CoseKey.dump_to_native(@sample_cose_key, [])
      assert is_binary(binary)
      assert {:ok, decoded, _} = CBOR.decode(binary)
      assert decoded == @sample_cose_key
    end
  end

  describe "cast_stored/2" do
    test "decodes CBOR binary to map" do
      cbor = CBOR.encode(@sample_cose_key) |> IO.iodata_to_binary()
      assert {:ok, decoded} = CoseKey.cast_stored(cbor, [])
      assert decoded == @sample_cose_key
    end

    test "rejects invalid CBOR" do
      assert :error = CoseKey.cast_stored("not-cbor", [])
    end
  end

  describe "round trip" do
    test "cast_input -> dump_to_native -> cast_stored preserves data" do
      {:ok, key} = CoseKey.cast_input(@sample_cose_key, [])
      {:ok, binary} = CoseKey.dump_to_native(key, [])
      {:ok, restored} = CoseKey.cast_stored(binary, [])
      assert restored == @sample_cose_key
    end
  end
end
