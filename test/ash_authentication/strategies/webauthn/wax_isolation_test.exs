# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.WaxIsolationTest do
  @moduledoc """
  The WebAuthn strategy is generic over its ceremony backend: only the Wax
  adapter may refer to Wax. Anything else that does would make a strategy
  configured with another adapter depend on `wax_` all the same.

  This parses every source file under `lib/` and fails on any alias rooted
  at `Wax` outside the adapters directory. Prose in docstrings is not an
  alias, so it is free to name Wax as the default adapter's backend.
  """
  use ExUnit.Case, async: true

  @moduletag feature: :webauthn

  @lib Path.expand("../../../../lib", __DIR__)
  @adapters Path.join(@lib, "ash_authentication/strategies/webauthn/adapters")

  test "only the Wax adapter references a Wax module" do
    offenders =
      [@lib, "**", "*.ex"]
      |> Path.join()
      |> Path.wildcard()
      |> Enum.reject(&String.starts_with?(&1, @adapters <> "/"))
      |> Enum.flat_map(&wax_references/1)

    assert offenders == [],
           """
           Wax must only be referenced from the Wax adapter \
           (lib/ash_authentication/strategies/webauthn/adapters/). Found:

           #{Enum.map_join(offenders, "\n", fn {file, line, alias} -> "  #{Path.relative_to(file, @lib)}:#{line}  #{alias}" end)}
           """
  end

  test "the scan recognises a Wax alias" do
    source = """
    defmodule Example do
      alias Wax.Challenge
      def loaded?, do: Code.ensure_loaded?(Wax)
      def mention, do: "Wax in a string is fine"
    end
    """

    assert [{_, 2, "Wax.Challenge"}, {_, 3, "Wax"}] = wax_references("example.ex", source)
  end

  defp wax_references(file), do: wax_references(file, File.read!(file))

  defp wax_references(file, source) do
    {_ast, references} =
      source
      |> Code.string_to_quoted!(file: file)
      |> Macro.prewalk([], fn
        {:__aliases__, meta, [:Wax | _] = parts} = node, acc ->
          {node, [{file, meta[:line], Enum.join(parts, ".")} | acc]}

        node, acc ->
          {node, acc}
      end)

    Enum.reverse(references)
  end
end
