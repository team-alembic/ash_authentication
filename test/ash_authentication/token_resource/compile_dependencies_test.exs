# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.TokenResource.CompileDependenciesTest do
  @moduledoc false
  use ExUnit.Case, async: true
  alias AshAuthentication.TokenResource.Info

  defmodule Domain do
    @moduledoc false
    use Ash.Domain, validate_config_inclusion?: false

    resources do
      allow_unregistered? true
    end
  end

  defmodule Endpoint do
    @moduledoc false
  end

  defmodule Token do
    @moduledoc false
    use Ash.Resource,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAuthentication.TokenResource],
      domain: Domain

    token do
      endpoints [Endpoint]
    end

    {compile_references, _exports, _runtime, _compile_env} =
      Kernel.LexicalTracker.references(__ENV__.lexical_tracker)

    @compile_references compile_references

    def compile_references, do: @compile_references
  end

  test "endpoints do not become compile-time dependencies of the token resource" do
    assert Info.token_endpoints!(Token) == [Endpoint]
    refute Endpoint in Token.compile_references()
  end
end
