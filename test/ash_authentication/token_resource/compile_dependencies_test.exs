# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.TokenResource.CompileDependenciesTest do
  @moduledoc false
  use ExUnit.Case, async: false
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

  defmodule Tracer do
    @moduledoc false
    def trace({:on_module, _, _}, env) do
      {compile, exports, _runtime, _compile_env} =
        Kernel.LexicalTracker.references(env.lexical_tracker)

      send(:persistent_term.get(__MODULE__), {:references, env.module, compile, exports})
      :ok
    end

    def trace(_event, _env), do: :ok
  end

  test "endpoints do not become compile-time dependencies of the token resource" do
    :persistent_term.put(Tracer, self())
    tracers = Code.get_compiler_option(:tracers)
    Code.put_compiler_option(:tracers, [Tracer | tracers])

    try do
      Code.compile_string("""
      defmodule AshAuthentication.TokenResource.CompileDependenciesTest.Token do
        use Ash.Resource,
          data_layer: Ash.DataLayer.Ets,
          extensions: [AshAuthentication.TokenResource],
          domain: AshAuthentication.TokenResource.CompileDependenciesTest.Domain

        alias AshAuthentication.TokenResource.CompileDependenciesTest.Endpoint

        token do
          endpoints [Endpoint]
        end
      end
      """)
    after
      Code.put_compiler_option(:tracers, tracers)
    end

    module = AshAuthentication.TokenResource.CompileDependenciesTest.Token
    assert_received {:references, ^module, compile, exports}

    refute Endpoint in compile
    refute Endpoint in exports
    assert Info.token_endpoints!(module) == [Endpoint]
  end
end
