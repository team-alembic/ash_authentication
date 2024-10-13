# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule AshAuthentication.Igniter do
  @moduledoc "Codemods for working with AshAuthentication"

  @doc "Adds a secret to a secret module that reads from application env"
  @spec add_secret_from_env(Igniter.t(), module(), Ash.Resource.t(), list(atom), atom()) ::
          Igniter.t()
  def add_secret_from_env(igniter, module, resource, path, env_key) do
    otp_app = Igniter.Project.Application.app_name(igniter)

    func =
      quote do
        def secret_for(unquote(path), unquote(resource), _opts),
          do: Application.fetch_env(unquote(otp_app), unquote(env_key))
      end

    full =
      quote do
        use AshAuthentication.Secret
        unquote(func)
      end
      |> Sourceror.to_string()

    Igniter.Project.Module.find_and_update_or_create_module(igniter, module, full, fn zipper ->
      {:ok, Igniter.Code.Common.add_code(zipper, func)}
    end)
  end

  @doc "Adds a new add_on to the authentication.strategies section of a resource"
  @spec add_new_add_on(
          Igniter.t(),
          Ash.Resource.t(),
          type :: atom,
          name :: atom,
          contents :: String.t()
        ) :: Igniter.t()
  def add_new_add_on(igniter, resource, type, name, contents) do
    {igniter, defines?} = defines_add_on(igniter, resource, type, name)

    if defines? do
      igniter
    else
      add_add_on(igniter, resource, contents)
    end
  end

  @doc "Adds an add on to the authentication.add_ons section of a resource"
  @spec add_add_on(
          Igniter.t(),
          Ash.Resource.t(),
          contents :: String.t()
        ) :: Igniter.t()
  def add_add_on(igniter, resource, contents) do
    Igniter.Project.Module.find_and_update_module!(igniter, resource, fn zipper ->
      with {:authentication, {:ok, zipper}} <-
             {:authentication, enter_section(zipper, :authentication)},
           {:add_ons, _authentication_zipper, {:ok, zipper}} <-
             {:add_ons, zipper, enter_section(zipper, :add_ons)} do
        {:ok, Igniter.Code.Common.add_code(zipper, contents)}
      else
        {:authentication, :error} ->
          {:ok,
           Igniter.Code.Common.add_code(zipper, """
           authentication do
             add_ons do
               #{contents}
             end
           end
           """)}

        {:add_ons, zipper, :error} ->
          {:ok,
           Igniter.Code.Common.add_code(zipper, """
           add_ons do
             #{contents}
           end
           """)}
      end
    end)
  end

  @doc "Returns true if the given resource defines an authentication add on with the provided name"
  @spec defines_add_on(Igniter.t(), Ash.Resource.t(), constructor :: atom(), name :: atom()) ::
          {Igniter.t(), true | false}
  def defines_add_on(igniter, resource, constructor, name) do
    Spark.Igniter.find(igniter, resource, fn _, zipper ->
      with {:ok, zipper} <- enter_section(zipper, :authentication),
           {:ok, zipper} <- enter_section(zipper, :add_ons),
           {:ok, _zipper} <-
             Igniter.Code.Function.move_to_function_call_in_current_scope(
               zipper,
               constructor,
               [1, 2],
               &Igniter.Code.Function.argument_equals?(&1, 0, name)
             ) do
        {:ok, true}
      else
        _ ->
          :error
      end
    end)
    |> case do
      {:ok, igniter, _module, _value} ->
        {igniter, true}

      {:error, igniter} ->
        {igniter, false}
    end
  end

  @doc "Adds a new strategy to the authentication.strategies section of a resource"
  @spec add_new_strategy(
          Igniter.t(),
          Ash.Resource.t(),
          type :: atom,
          name :: atom,
          contents :: String.t()
        ) :: Igniter.t()
  def add_new_strategy(igniter, resource, type, name, contents) do
    {igniter, defines?} = defines_strategy(igniter, resource, type, name)

    if defines? do
      igniter
    else
      add_strategy(igniter, resource, contents)
    end
  end

  @doc "Adds a strategy to the authentication.strategies section of a resource"
  @spec add_strategy(
          Igniter.t(),
          Ash.Resource.t(),
          contents :: String.t()
        ) :: Igniter.t()
  def add_strategy(igniter, resource, contents) do
    Igniter.Project.Module.find_and_update_module!(igniter, resource, fn zipper ->
      with {:authentication, {:ok, zipper}} <-
             {:authentication, enter_section(zipper, :authentication)},
           {:strategies, _authentication_zipper, {:ok, zipper}} <-
             {:strategies, zipper, enter_section(zipper, :strategies)} do
        {:ok, Igniter.Code.Common.add_code(zipper, contents)}
      else
        {:authentication, :error} ->
          {:ok,
           Igniter.Code.Common.add_code(zipper, """
           authentication do
             strategies do
               #{contents}
             end
           end
           """)}

        {:strategies, zipper, :error} ->
          {:ok,
           Igniter.Code.Common.add_code(zipper, """
           strategies do
             #{contents}
           end
           """)}
      end
    end)
  end

  @doc "Returns true if the given resource defines an authentication strategy with the provided name"
  @spec defines_strategy(Igniter.t(), Ash.Resource.t(), constructor :: atom(), name :: atom()) ::
          {Igniter.t(), true | false}
  def defines_strategy(igniter, resource, constructor, name) do
    Spark.Igniter.find(igniter, resource, fn _, zipper ->
      with {:ok, zipper} <- enter_section(zipper, :authentication),
           {:ok, zipper} <- enter_section(zipper, :strategies),
           {:ok, _zipper} <-
             Igniter.Code.Function.move_to_function_call_in_current_scope(
               zipper,
               constructor,
               [1, 2],
               &Igniter.Code.Function.argument_equals?(&1, 0, name)
             ) do
        {:ok, true}
      else
        _ ->
          :error
      end
    end)
    |> case do
      {:ok, igniter, _module, _value} ->
        {igniter, true}

      {:error, igniter} ->
        {igniter, false}
    end
  end

  defp enter_section(zipper, name) do
    with {:ok, zipper} <-
           Igniter.Code.Function.move_to_function_call_in_current_scope(
             zipper,
             name,
             1
           ) do
      Igniter.Code.Common.move_to_do_block(zipper)
    end
  end
end
