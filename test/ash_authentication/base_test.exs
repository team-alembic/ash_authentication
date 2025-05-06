defmodule AshAuthentication.BaseTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use ExUnitProperties

  property "binencode62/1 and decode62/1 are inverses" do
    check all(input <- binary(), !String.starts_with?(input, <<0>>)) do
      encoded = AshAuthentication.Base.encode62(input)
      {:ok, decoded} = AshAuthentication.Base.bindecode62(encoded)
      assert decoded == input
    end
  end

  test "bindecode62/1 handles invalid inputs" do
    assert :error = AshAuthentication.Base.bindecode62("invalid_base62+/$")
    assert :error = AshAuthentication.Base.bindecode62("!@#")

    assert :error = AshAuthentication.Base.bindecode62(nil)
  end
end
