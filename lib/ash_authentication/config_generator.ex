defmodule AshAuthentication.ConfigGenerator do
  @moduledoc """
  Used to dynamically generate configuration functions for Spark extensions
  based on their DSL.

  ## Usage

  ```elixir
  defmodule MyConfig do
    use AshAuthentication.ConfigGenerator, extension: MyDslExtension, section: :my_section
  end
  ```
  """

  @doc false
  @spec __using__(keyword) :: Macro.t()
  defmacro __using__(opts) do
    extension = Keyword.fetch!(opts, :extension)
    section = Keyword.fetch!(opts, :section)

    quote do
      require unquote(extension)

      AshAuthentication.ConfigGenerator.generate_options_function(
        unquote(extension),
        unquote(section)
      )

      AshAuthentication.ConfigGenerator.generate_config_functions(
        unquote(extension),
        unquote(section)
      )
    end
  end

  @doc false
  @spec generate_config_functions(module, atom) :: Macro.t()
  defmacro generate_config_functions(extension, section) do
    options =
      extension
      |> Macro.expand_literal(__ENV__)
      |> apply(:sections, [])
      |> Enum.find(&(&1.name == section))
      |> Map.get(:schema, [])

    for {name, opts} <- options do
      spec = AshAuthentication.Utils.spec_for_option(opts)

      quote generated: true do
        @doc unquote(Keyword.get(opts, :doc, false))
        @spec unquote(name)(dsl_or_resource :: module | map) :: {:ok, unquote(spec)} | :error

        def unquote(name)(dsl_or_resource) do
          import Spark.Dsl.Extension, only: [get_opt: 4]

          case get_opt(dsl_or_resource, [unquote(section)], unquote(name), :error) do
            :error -> :error
            value -> {:ok, value}
          end
        end

        @doc unquote(Keyword.get(opts, :doc, false))
        @spec unquote(:"#{name}!")(dsl_or_resource :: module | map) :: unquote(spec) | no_return

        def unquote(:"#{name}!")(dsl_or_resource) do
          case unquote(name)(dsl_or_resource) do
            {:ok, value} ->
              value

            :error ->
              raise "No configuration for `#{unquote(name)}` present on `#{inspect(dsl_or_resource)}`."
          end
        end
      end
    end
  end

  @doc false
  @spec generate_options_function(module, atom) :: Macro.t()
  defmacro generate_options_function(extension, section) do
    options =
      extension
      |> Macro.expand_literal(__ENV__)
      |> apply(:sections, [])
      |> Enum.find(&(&1.name == section))
      |> Map.get(:schema, [])

    quote generated: true do
      @doc """
      The DSL options

      Returns a map containing the schema and any configured or default values.
      """
      @spec options(dsl_or_resource :: module | map) :: %{required(atom) => any}
      def options(dsl_or_resource) do
        import Spark.Dsl.Extension, only: [get_opt: 3]

        Enum.reduce(unquote(options), %{}, fn {name, opts}, result ->
          with nil <- get_opt(dsl_or_resource, [unquote(section)], name),
               nil <- Keyword.get(opts, :default) do
            result
          else
            value -> Map.put(result, name, value)
          end
        end)
      end
    end
  end
end
