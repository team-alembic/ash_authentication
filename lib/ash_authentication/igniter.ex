# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule AshAuthentication.Igniter do
    @moduledoc "Codemods for working with AshAuthentication"

    @doc "Adds a secret to a secret module that reads from application env, if one for that module/path doesn't exist already."
    @spec add_new_secret_from_env(Igniter.t(), module(), Ash.Resource.t(), list(atom), atom()) ::
            Igniter.t()
    def add_new_secret_from_env(igniter, module, resource, path, env_key) do
      otp_app = Igniter.Project.Application.app_name(igniter)

      func =
        quote do
          def secret_for(unquote(path), unquote(resource), _opts, _context),
            do: Application.fetch_env(unquote(otp_app), unquote(env_key))
        end

      full =
        quote do
          use AshAuthentication.Secret
          unquote(func)
        end
        |> Sourceror.to_string()

      Igniter.Project.Module.find_and_update_or_create_module(igniter, module, full, fn zipper ->
        with {:ok, zipper} <-
               Igniter.Code.Function.move_to_def(zipper, :secret_for, 4, target: :at),
             zipper when not is_nil(zipper) <- Sourceror.Zipper.down(zipper),
             zipper when not is_nil(zipper) <- Sourceror.Zipper.down(zipper),
             true <- Igniter.Code.Common.nodes_equal?(zipper, path),
             zipper when not is_nil(zipper) <- Sourceror.Zipper.right(zipper),
             true <- Igniter.Code.Common.nodes_equal?(zipper, resource) do
          {:ok, zipper}
        else
          _ ->
            {:ok, Igniter.Code.Common.add_code(zipper, func)}
        end
      end)
    end

    @doc "Adds a secret to a secret module that reads from application env"
    @spec add_secret_from_env(Igniter.t(), module(), Ash.Resource.t(), list(atom), atom()) ::
            Igniter.t()
    def add_secret_from_env(igniter, module, resource, path, env_key) do
      otp_app = Igniter.Project.Application.app_name(igniter)

      func =
        quote do
          def secret_for(unquote(path), unquote(resource), _opts, _context),
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
            name :: atom | nil,
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
                 &add_on_matches?(&1, name)
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

    defp add_on_matches?(zipper, nil) do
      Igniter.Code.Function.move_to_nth_argument(zipper, 1) == :error
    end

    defp add_on_matches?(zipper, name) do
      Igniter.Code.Function.argument_equals?(zipper, 0, name)
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

    @doc "Returns true if the given resource defines an authentication strategy of the provided type"
    @spec defines_strategy_of_type(
            Igniter.t(),
            Ash.Resource.t(),
            constructor :: atom()
          ) ::
            {Igniter.t(), true | false}
    def defines_strategy_of_type(igniter, resource, constructor) do
      Spark.Igniter.find(igniter, resource, fn _, zipper ->
        with {:ok, zipper} <- enter_section(zipper, :authentication),
             {:ok, zipper} <- enter_section(zipper, :strategies),
             {:ok, _zipper} <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(
                 zipper,
                 constructor,
                 [1, 2]
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

    @doc """
    Ensures a unique identity exists for the given field on a resource.

    Adds an identity named `:unique_<field>` on `[:<field>]` if one doesn't already exist.
    """
    @spec ensure_identity(Igniter.t(), Ash.Resource.t(), atom()) :: Igniter.t()
    # sobelow_skip ["DOS.BinToAtom"]
    def ensure_identity(igniter, resource, identity_field) do
      Ash.Resource.Igniter.add_new_identity(
        igniter,
        resource,
        :"unique_#{identity_field}",
        """
        identity :unique_#{identity_field}, [:#{identity_field}]
        """
      )
    end

    @doc """
    Ensures a `get_by_<field>` read action exists on the resource.
    """
    @spec ensure_get_by_action(Igniter.t(), Ash.Resource.t(), atom()) :: Igniter.t()
    # sobelow_skip ["DOS.BinToAtom"]
    def ensure_get_by_action(igniter, resource, identity_field) do
      Ash.Resource.Igniter.add_new_action(
        igniter,
        resource,
        :"get_by_#{identity_field}",
        """
        read :get_by_#{identity_field} do
          description "Looks up a user by their #{identity_field}"
          get_by :#{identity_field}
        end
        """
      )
    end

    @doc """
    Adds the `remember_me` strategy to a resource if it doesn't already exist.
    """
    @spec add_remember_me_strategy(Igniter.t(), Ash.Resource.t()) :: Igniter.t()
    def add_remember_me_strategy(igniter, resource) do
      add_new_strategy(
        igniter,
        resource,
        :remember_me,
        :remember_me,
        """
        remember_me :remember_me
        """
      )
    end

    @doc """
    Returns the parent module of a given module.

    Useful for deriving a domain module from a resource module.

    ## Example

        iex> AshAuthentication.Igniter.parent_module(MyApp.Accounts.User)
        MyApp.Accounts
    """
    @spec parent_module(module()) :: module()
    def parent_module(module) do
      module |> Module.split() |> :lists.droplast() |> Module.concat()
    end

    @doc """
    Parses a module from a string, or returns an atom as-is.
    """
    @spec maybe_parse_module(atom() | String.t()) :: module()
    def maybe_parse_module(atom) when is_atom(atom), do: atom

    def maybe_parse_module(string) when is_binary(string),
      do: Igniter.Project.Module.parse(string)

    @doc """
    Runs `Ash.Igniter.codegen/2` with a consistent migration name for a strategy.

    ## Example

        codegen_for_strategy(igniter, :password)
        # => codegen named "add_password_auth_strategy"
    """
    @spec codegen_for_strategy(Igniter.t(), atom()) :: Igniter.t()
    def codegen_for_strategy(igniter, strategy_name) do
      Ash.Igniter.codegen(igniter, "add_#{strategy_name}_auth_strategy")
    end

    @doc """
    Ensures a UserIdentity resource exists for the given user resource.

    If the identity resource module already exists, this is a no-op.
    Otherwise, generates a new resource with the `AshAuthentication.UserIdentity`
    extension. The extension auto-generates all attributes, relationships, actions,
    and identities — this function only creates the resource shell.
    """
    @spec ensure_user_identity_resource(Igniter.t(), module(), module()) :: Igniter.t()
    def ensure_user_identity_resource(igniter, user_resource, identity_resource) do
      {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, identity_resource)

      if exists? do
        igniter
      else
        igniter
        |> Igniter.compose_task(
          "ash.gen.resource",
          [inspect(identity_resource), "--default-actions", "read"] ++
            data_layer_extension_args()
        )
        |> Igniter.compose_task(
          "ash.extend",
          [inspect(identity_resource), "AshAuthentication.UserIdentity,Ash.Policy.Authorizer"]
        )
        |> Spark.Igniter.set_option(
          identity_resource,
          [:user_identity, :user_resource],
          user_resource
        )
        |> maybe_set_postgres_table(identity_resource)
        |> Ash.Resource.Igniter.add_bypass(
          identity_resource,
          quote do
            AshAuthentication.Checks.AshAuthenticationInteraction
          end,
          quote do
            authorize_if always()
          end
        )
      end
    end

    @doc """
    Adds an OAuth2 register action to a user resource.

    The action handles both registration and sign-in via `upsert? true`.
    It satisfies the OAuth2 transformer's validation requirements.
    """
    @spec add_oauth_register_action(Igniter.t(), module(), atom(), keyword()) :: Igniter.t()
    # sobelow_skip ["DOS.BinToAtom"]
    def add_oauth_register_action(igniter, user_resource, strategy_name, opts \\ []) do
      identity_field = Keyword.get(opts, :identity_field, :email)
      identity_resource = Keyword.get(opts, :identity_resource)

      identity_change_line =
        if identity_resource do
          "change AshAuthentication.Strategy.OAuth2.IdentityChange"
        else
          ""
        end

      Ash.Resource.Igniter.add_new_action(
        igniter,
        user_resource,
        :"register_with_#{strategy_name}",
        """
        create :register_with_#{strategy_name} do
          argument :user_info, :map, allow_nil?: false
          argument :oauth_tokens, :map, allow_nil?: false
          upsert? true
          upsert_identity :unique_#{identity_field}

          change AshAuthentication.GenerateTokenChange
          #{identity_change_line}

          change {AshAuthentication.Strategy.OAuth2.UserInfoToAttributes, fields: [#{inspect(identity_field)}]}
        end
        """
      )
    end

    @doc """
    Wires OAuth secrets into the secrets module and runtime.exs.

    For each `{secret_key, env_var_name}` pair:
    - Adds a `secret_for/4` clause to the secrets module
    - Adds a `System.get_env` entry to runtime.exs
    """
    @spec add_oauth_secrets(
            Igniter.t(),
            module(),
            module(),
            atom(),
            list({atom(), String.t()})
          ) :: Igniter.t()
    # sobelow_skip ["DOS.StringToAtom"]
    def add_oauth_secrets(igniter, secrets_module, user_resource, strategy_name, secret_pairs) do
      otp_app = Igniter.Project.Application.app_name(igniter)

      Enum.reduce(secret_pairs, igniter, fn {secret_key, env_var_name}, igniter ->
        env_key_atom = String.to_atom(String.downcase(env_var_name))

        runtime_value =
          {:code,
           Sourceror.parse_string!("""
           System.get_env("#{env_var_name}")
           """)}

        igniter
        |> add_new_secret_from_env(
          secrets_module,
          user_resource,
          [:authentication, :strategies, strategy_name, secret_key],
          env_key_atom
        )
        |> Igniter.Project.Config.configure(
          "runtime.exs",
          otp_app,
          [env_key_atom],
          runtime_value
        )
      end)
    end

    defp maybe_set_postgres_table(igniter, resource) do
      if Code.ensure_loaded?(AshPostgres.DataLayer) do
        Spark.Igniter.set_option(igniter, resource, [:postgres, :table], "user_identities")
      else
        igniter
      end
    end

    defp data_layer_extension_args do
      cond do
        Code.ensure_loaded?(AshPostgres.DataLayer) -> ["--extend", "postgres"]
        Code.ensure_loaded?(AshSqlite.DataLayer) -> ["--extend", "sqlite"]
        true -> []
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
end
