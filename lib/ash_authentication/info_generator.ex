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
    extension = Keyword.fetch!(opts, :extension) |> Macro.expand(__CALLER__)
    sections = Keyword.get(opts, :sections, [])
    prefix? = Keyword.get(opts, :prefix?, false)

    quote do
      require AshAuthentication.InfoGenerator
      require unquote(extension)

      AshAuthentication.InfoGenerator.generate_config_functions(
        unquote(extension),
        unquote(sections),
        unquote(prefix?)
      )

      AshAuthentication.InfoGenerator.generate_options_functions(
        unquote(extension),
        unquote(sections),
        unquote(prefix?)
      )
    end
  end

  @doc """
  Given an extension and a list of DSL sections, generate an options function
  which returns a map of all configured options for a resource (including
  defaults).
  """
  @spec generate_options_functions(module, [atom], boolean) :: Macro.t()
  defmacro generate_options_functions(_extension, sections, false) when length(sections) > 1,
    do: raise("Cannot generate options functions for more than one section without prefixes.")

  defmacro generate_options_functions(extension, sections, prefix?) do
    for {section, options} <- extension_sections_to_list(extension, sections) do
      function_name = if prefix?, do: :"#{section}_options", else: :options

      quote location: :keep do
        @doc """
        #{unquote(section)} DSL options

        Returns a map containing the and any configured or default values.
        """
        @spec unquote(function_name)(dsl_or_resource :: module | map) :: %{required(atom) => any}
        def unquote(function_name)(dsl_or_resource) do
          import Spark.Dsl.Extension, only: [get_opt: 4]

          unquote(Macro.escape(options))
          |> Stream.map(fn option ->
            value =
              dsl_or_resource
              |> get_opt([option.section], option.name, Map.get(option, :default))

            {option.name, value}
          end)
          |> Stream.reject(&is_nil(elem(&1, 1)))
          |> Map.new()
        end
      end
    end
  end

  @doc """
  Given an extension and a list of DSL sections generate individual config
  functions for each option.
  """
  @spec generate_config_functions(module, [atom], boolean) :: Macro.t()
  defmacro generate_config_functions(extension, sections, prefix?) do
    for {_, options} <- extension_sections_to_list(extension, sections) do
      for option <- options do
        function_name = if prefix?, do: :"#{option.section}_#{option.name}", else: option.name

        option
        |> Map.put(:function_name, function_name)
        |> generate_config_function()
      end
    end
  end

  defp extension_sections_to_list(extension, sections) do
    extension.sections()
    |> Stream.map(fn section ->
      schema =
        section.schema
        |> Enum.map(fn {name, opts} ->
          opts
          |> Map.new()
          |> Map.take(~w[type doc default]a)
          |> Map.update!(:type, &spec_for_type/1)
          |> Map.put(:pred?, name |> to_string() |> String.ends_with?("?"))
          |> Map.put(:name, name)
          |> Map.put(:section, section.name)
        end)

      {section.name, schema}
    end)
    |> Map.new()
    |> Map.take(sections)
  end

  defp generate_config_function(%{pred?: true} = option) do
    quote location: :keep do
      @doc unquote(option.doc)
      @spec unquote(option.function_name)(dsl_or_resource :: module | map) ::
              unquote(option.type)
      def unquote(option.function_name)(dsl_or_resource) do
        import Spark.Dsl.Extension, only: [get_opt: 4]

        get_opt(
          dsl_or_resource,
          [unquote(option.section)],
          unquote(option.name),
          unquote(option.default)
        )
      end
    end
  end

  defp generate_config_function(option) do
    quote location: :keep do
      @doc unquote(Map.get(option, :doc, false))
      @spec unquote(option.function_name)(dsl_or_resource :: module | map) ::
              {:ok, unquote(option.type)} | :error

      def unquote(option.function_name)(dsl_or_resource) do
        import Spark.Dsl.Extension, only: [get_opt: 4]

        case get_opt(
               dsl_or_resource,
               [unquote(option.section)],
               unquote(option.name),
               unquote(Map.get(option, :default, :error))
             ) do
          :error -> :error
          value -> {:ok, value}
        end
      end

      @doc unquote(Map.get(option, :doc, false))
      @spec unquote(:"#{option.function_name}!")(dsl_or_resource :: module | map) ::
              unquote(option.type) | no_return

      def unquote(:"#{option.function_name}!")(dsl_or_resource) do
        import Spark.Dsl.Extension, only: [get_opt: 4]

        case get_opt(
               dsl_or_resource,
               [unquote(option.section)],
               unquote(option.name),
               unquote(Map.get(option, :default, :error))
             ) do
          :error ->
            raise "No configuration for `#{unquote(option.name)}` present on `#{inspect(dsl_or_resource)}`."

          value ->
            value
        end
      end
    end
  end

  defp spec_for_type({:behaviour, _module}), do: {:module, [], Elixir}

  defp spec_for_type({:spark_function_behaviour, behaviour, {_, arity}}),
    do:
      spec_for_type(
        {:or,
         [
           {:behaviour, behaviour},
           {{:behaviour, behaviour}, {:keyword, [], Elixir}},
           {:fun, arity}
         ]}
      )

  defp spec_for_type({:fun, arity}) do
    args =
      0..(arity - 1)
      |> Enum.map(fn _ -> {:any, [], Elixir} end)

    [{:->, [], [args, {:any, [], Elixir}]}]
  end

  defp spec_for_type({:or, [type]}), do: spec_for_type(type)

  defp spec_for_type({:or, [next | remaining]}),
    do: {:|, [], [spec_for_type(next), spec_for_type({:or, remaining})]}

  defp spec_for_type({:in, %Range{first: first, last: last}})
       when is_integer(first) and is_integer(last),
       do: {:.., [], [first, last]}

  defp spec_for_type({:in, %Range{first: first, last: last}}),
    do:
      {{:., [], [{:__aliases__, [], [:Range]}, :t]}, [],
       [spec_for_type(first), spec_for_type(last)]}

  defp spec_for_type({:in, [type]}), do: spec_for_type(type)

  defp spec_for_type({:in, [next | remaining]}),
    do: {:|, [], [spec_for_type(next), spec_for_type({:in, remaining})]}

  defp spec_for_type({:list, subtype}), do: [spec_for_type(subtype)]

  defp spec_for_type({:custom, _, _, _}), do: spec_for_type(:any)

  defp spec_for_type({:tuple, subtypes}) do
    subtypes
    |> Enum.map(&spec_for_type/1)
    |> List.to_tuple()
  end

  defp spec_for_type(:string),
    do: {{:., [], [{:__aliases__, [alias: false], [:String]}, :t]}, [], []}

  defp spec_for_type(terminal)
       when terminal in ~w[any map atom string boolean integer non_neg_integer pos_integer float timeout pid reference mfa]a,
       do: {terminal, [], Elixir}

  defp spec_for_type(atom) when is_atom(atom), do: atom
  defp spec_for_type(number) when is_number(number), do: number
  defp spec_for_type(string) when is_binary(string), do: spec_for_type(:string)

  defp spec_for_type({mod, arg}) when is_atom(mod) and is_list(arg),
    do: {{:module, [], Elixir}, {:list, [], Elixir}}

  defp spec_for_type(tuple) when is_tuple(tuple),
    do: tuple |> Tuple.to_list() |> Enum.map(&spec_for_type/1) |> List.to_tuple()

  defp spec_for_type([]), do: []
  defp spec_for_type([type]), do: [spec_for_type(type)]
end
