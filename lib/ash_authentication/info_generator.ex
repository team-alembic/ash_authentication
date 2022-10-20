defmodule AshAuthentication.InfoGenerator do
  @moduledoc """
  Used to dynamically generate configuration functions for Spark extensions
  based on their DSL.

  ## Usage

  ```elixir
  defmodule MyConfig do
    use AshAuthentication.InfoGenerator, extension: MyDslExtension, sections: [:my_section]
  end
  ```
  """

  @type options :: [{:extension, module} | {:sections, [atom]} | {:prefix?, boolean}]

  @doc false
  @spec __using__(options) :: Macro.t()
  defmacro __using__(opts) do
    extension = Keyword.fetch!(opts, :extension)
    sections = Keyword.get(opts, :sections, [])
    prefix? = Keyword.get(opts, :prefix?, false)

    quote do
      require unquote(extension)
    end

    for section <- sections do
      quote do
        AshAuthentication.InfoGenerator.generate_options_function(
          unquote(extension),
          unquote(section),
          unquote(prefix?)
        )

        AshAuthentication.InfoGenerator.generate_config_functions(
          unquote(extension),
          unquote(section),
          unquote(prefix?)
        )
      end
    end
  end

  @doc false
  @spec generate_config_functions(module, atom, boolean) :: Macro.t()
  defmacro generate_config_functions(extension, section, prefix?) do
    options =
      extension
      |> Macro.expand_literal(__ENV__)
      |> apply(:sections, [])
      |> Enum.find(&(&1.name == section))
      |> Map.get(:schema, [])

    for {name, opts} <- options do
      pred? = name |> to_string() |> String.ends_with?("?")
      function_name = if prefix?, do: :"#{section}_#{name}", else: name

      if pred? do
        generate_predicate_function(function_name, section, name, Keyword.get(opts, :doc, false))
      else
        spec = AshAuthentication.Utils.spec_for_option(opts)

        quote generated: true do
          unquote(
            generate_config_function(
              function_name,
              section,
              name,
              Keyword.get(opts, :doc, false),
              spec
            )
          )

          unquote(
            generate_config_bang_function(
              function_name,
              section,
              name,
              Keyword.get(opts, :doc, false),
              spec
            )
          )
        end
      end
    end
  end

  defp generate_predicate_function(function_name, section, name, doc) do
    quote generated: true do
      @doc unquote(doc)
      @spec unquote(function_name)(dsl_or_resource :: module | map) :: boolean
      def unquote(function_name)(dsl_or_resource) do
        import Spark.Dsl.Extension, only: [get_opt: 4]
        get_opt(dsl_or_resource, [unquote(section)], unquote(name), false)
      end
    end
  end

  defp generate_config_function(function_name, section, name, doc, spec) do
    quote generated: true do
      @doc unquote(doc)
      @spec unquote(function_name)(dsl_or_resource :: module | map) ::
              {:ok, unquote(spec)} | :error

      def unquote(function_name)(dsl_or_resource) do
        import Spark.Dsl.Extension, only: [get_opt: 4]

        case get_opt(dsl_or_resource, [unquote(section)], unquote(name), :error) do
          :error -> :error
          value -> {:ok, value}
        end
      end
    end
  end

  defp generate_config_bang_function(function_name, section, name, doc, spec) do
    quote generated: true do
      @doc unquote(doc)
      @spec unquote(:"#{function_name}!")(dsl_or_resource :: module | map) ::
              unquote(spec) | no_return

      def unquote(:"#{function_name}!")(dsl_or_resource) do
        import Spark.Dsl.Extension, only: [get_opt: 4]

        case get_opt(dsl_or_resource, [unquote(section)], unquote(name), :error) do
          :error ->
            raise "No configuration for `#{unquote(name)}` present on `#{inspect(dsl_or_resource)}`."

          value ->
            value
        end
      end
    end
  end

  @doc false
  @spec generate_options_function(module, atom, boolean) :: Macro.t()
  defmacro generate_options_function(extension, section, prefix?) do
    options =
      extension
      |> Macro.expand_literal(__ENV__)
      |> apply(:sections, [])
      |> Enum.find(&(&1.name == section))
      |> Map.get(:schema, [])

    function_name = if prefix?, do: :"#{section}_options", else: :options

    quote generated: true do
      @doc """
      The DSL options

      Returns a map containing the schema and any configured or default values.
      """
      @spec unquote(function_name)(dsl_or_resource :: module | map) :: %{required(atom) => any}
      def unquote(function_name)(dsl_or_resource) do
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
