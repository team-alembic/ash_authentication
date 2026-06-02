# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AshAuthentication.Upgrade do
    @moduledoc false

    use Igniter.Mix.Task

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        # Groups allow for overlapping arguments for tasks by the same author
        # See the generators guide for more.
        group: :ash_authentication,
        # *other* dependencies to add
        # i.e `{:foo, "~> 2.0"}`
        adds_deps: [],
        # *other* dependencies to add and call their associated installers, if they exist
        # i.e `{:foo, "~> 2.0"}`
        installs: [],
        # An example invocation
        # example: __MODULE__.Docs.example(),
        example: "example",
        # a list of positional arguments, i.e `[:file]`
        positional: [:from, :to],
        # Other tasks your task composes using `Igniter.compose_task`, passing in the CLI argv
        # This ensures your option schema includes options from nested tasks
        composes: [],
        # `OptionParser` schema
        schema: [],
        # Default values for the options in the `schema`
        defaults: [],
        # CLI aliases
        aliases: [],
        # A list of options in the schema that are required
        required: []
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      positional = igniter.args.positional
      options = igniter.args.options

      upgrades =
        %{
          "4.4.9" => [&fix_token_is_revoked_action/2],
          "4.13.4" => [&add_remember_me_to_magic_link_sign_in/2],
          "4.14.0" => [&require_identity_resource/2]
        }

      # For each version that requires a change, add it to this map
      # Each key is a version that points at a list of functions that take an
      # igniter and options (i.e. flags or other custom options).
      # See the upgrades guide for more.
      Igniter.Upgrades.run(igniter, positional.from, positional.to, upgrades,
        custom_opts: options
      )
    end

    def fix_token_is_revoked_action(igniter, _opts) do
      case find_all_token_resources(igniter) do
        {igniter, []} ->
          igniter

        {igniter, resources} ->
          Enum.reduce(resources, igniter, fn resource, igniter ->
            maybe_fix_is_revoked_action(igniter, resource)
          end)
      end
    end

    defp find_all_token_resources(igniter) do
      Igniter.Project.Module.find_all_matching_modules(igniter, fn _module, zipper ->
        with {:ok, zipper} <- Igniter.Code.Module.move_to_use(zipper, Ash.Resource),
             {:ok, zipper} <- Igniter.Code.Function.move_to_nth_argument(zipper, 1),
             {:ok, zipper} <- Igniter.Code.Keyword.get_key(zipper, :extensions) do
          if Igniter.Code.List.list?(zipper) do
            match?(
              {:ok, _},
              Igniter.Code.List.move_to_list_item(
                zipper,
                &Igniter.Code.Common.nodes_equal?(&1, AshAuthentication.TokenResource)
              )
            )
          else
            Igniter.Code.Common.nodes_equal?(zipper, AshAuthentication.TokenResource)
          end
        end
      end)
    end

    defp maybe_fix_is_revoked_action(igniter, resource) do
      Igniter.Project.Module.find_and_update_module!(igniter, resource, fn zipper ->
        with {:ok, action_zipper} <- move_to_action(zipper, :action, :revoked?),
             {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(action_zipper),
             {:ok, zipper} <- remove_argument_option(zipper, :token, :allow_nil?),
             {:ok, zipper} <- remove_argument_option(zipper, :jti, :allow_nil?) do
          add_action_return_type(zipper, :boolean)
        else
          :error -> {:ok, zipper}
        end
      end)
    end

    defp move_to_action(zipper, type, name) do
      Igniter.Code.Function.move_to_function_call(
        zipper,
        type,
        2,
        &Igniter.Code.Function.argument_equals?(&1, 0, name)
      )
    end

    defp add_action_return_type(zipper, type) do
      zipper = Sourceror.Zipper.top(zipper)

      with {:ok, zipper} <- move_to_action(zipper, :action, :revoked?),
           {:ok, zipper} <- Igniter.Code.Function.move_to_nth_argument(zipper, 1) do
        {:ok,
         Sourceror.Zipper.insert_left(
           zipper,
           quote do
             unquote(type)
           end
         )}
      end
    end

    defp remove_argument_option(zipper, argument_name, option) do
      with {:ok, zipper} <-
             Igniter.Code.Function.move_to_function_call(
               zipper,
               :argument,
               3,
               &Igniter.Code.Function.argument_equals?(&1, 0, argument_name)
             ),
           {:ok, zipper} <- Igniter.Code.Function.move_to_nth_argument(zipper, 2) do
        if Igniter.Code.List.find_list_item_index(
             zipper,
             &Igniter.Code.Tuple.elem_equals?(&1, 0, :do)
           ) do
          Igniter.Code.Common.within(zipper, fn zipper ->
            {:ok,
             Igniter.Code.Common.remove(
               zipper,
               &Igniter.Code.Function.function_call?(&1, option, 1)
             )}
          end)
        else
          Igniter.Code.List.remove_from_list(
            zipper,
            &Igniter.Code.Tuple.elem_equals?(&1, 0, option)
          )
        end
      end
    end

    def add_remember_me_to_magic_link_sign_in(igniter, _opts) do
      case find_resources_with_magic_link_and_remember_me(igniter) do
        {igniter, []} ->
          igniter

        {igniter, resources} ->
          Enum.reduce(resources, igniter, fn resource, igniter ->
            maybe_add_remember_me_to_magic_link_action(igniter, resource)
          end)
      end
    end

    defp find_resources_with_magic_link_and_remember_me(igniter) do
      Igniter.Project.Module.find_all_matching_modules(igniter, fn _module, zipper ->
        with {:ok, zipper} <- enter_auth_strategies(zipper),
             true <- has_strategy?(zipper, :magic_link),
             true <- has_strategy?(zipper, :remember_me) do
          true
        else
          _ -> false
        end
      end)
    end

    defp enter_auth_strategies(zipper) do
      with {:ok, zipper} <-
             Igniter.Code.Function.move_to_function_call_in_current_scope(
               zipper,
               :authentication,
               1
             ),
           {:ok, zipper} <- Igniter.Code.Common.move_to_do_block(zipper),
           {:ok, zipper} <-
             Igniter.Code.Function.move_to_function_call_in_current_scope(
               zipper,
               :strategies,
               1
             ) do
        Igniter.Code.Common.move_to_do_block(zipper)
      end
    end

    defp has_strategy?(zipper, strategy_type) do
      match?(
        {:ok, _},
        Igniter.Code.Function.move_to_function_call_in_current_scope(
          zipper,
          strategy_type,
          [1, 2]
        )
      )
    end

    defp maybe_add_remember_me_to_magic_link_action(igniter, resource) do
      Igniter.Project.Module.find_and_update_module!(igniter, resource, fn zipper ->
        with {:ok, action_zipper} <- move_to_action(zipper, :create, :sign_in_with_magic_link),
             {:ok, do_block_zipper} <- Igniter.Code.Common.move_to_do_block(action_zipper) do
          do_block_zipper
          |> maybe_add_remember_me_argument()
          |> maybe_add_remember_me_change()
        else
          :error -> {:ok, zipper}
        end
      end)
    end

    defp maybe_add_remember_me_argument(zipper) do
      if has_remember_me_argument?(zipper) do
        zipper
      else
        add_remember_me_argument(zipper)
      end
    end

    defp has_remember_me_argument?(zipper) do
      match?(
        {:ok, _},
        Igniter.Code.Function.move_to_function_call_in_current_scope(
          zipper,
          :argument,
          [2, 3],
          &Igniter.Code.Function.argument_equals?(&1, 0, :remember_me)
        )
      )
    end

    defp add_remember_me_argument(zipper) do
      argument_code = """
      argument :remember_me, :boolean do
        description "Whether to generate a remember me token"
        allow_nil? true
      end
      """

      Igniter.Code.Common.add_code(zipper, argument_code)
    end

    defp maybe_add_remember_me_change(zipper) do
      if has_remember_me_change?(zipper) do
        {:ok, zipper}
      else
        {:ok, add_remember_me_change(zipper)}
      end
    end

    defp has_remember_me_change?(zipper) do
      match?(
        {:ok, _},
        Igniter.Code.Function.move_to_function_call_in_current_scope(
          zipper,
          :change,
          1,
          fn change_zipper ->
            case Igniter.Code.Function.move_to_nth_argument(change_zipper, 0) do
              {:ok, arg_zipper} ->
                source = Sourceror.Zipper.node(arg_zipper) |> Sourceror.to_string()
                String.contains?(source, "MaybeGenerateTokenChange")

              _ ->
                false
            end
          end
        )
      )
    end

    defp add_remember_me_change(zipper) do
      change_code = """
      change {AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenChange,
              strategy_name: :remember_me}
      """

      Igniter.Code.Common.add_code(zipper, change_code)
    end

    @oauth2_family ~w[oauth2 oidc github google auth0 apple slack]a

    def require_identity_resource(igniter, _opts) do
      case find_resources_with_oauth2_strategies(igniter) do
        {igniter, []} ->
          igniter

        {igniter, resources} ->
          resources
          |> Enum.reduce(igniter, &ensure_identity_resource/2)
          |> Igniter.add_notice("""
          The user identity resource's unique key changed from
          `(strategy, uid, user_id)` to `(strategy, uid)`, so that a provider's
          `iss`/`sub` resolves to exactly one local user.

          Run `mix ash.codegen require_user_identity_unique_key` (and then
          `mix ash.migrate`) to generate the migration that swaps the unique
          index.

          IMPORTANT: the new index will fail to create if your data contains the
          same `(strategy, uid)` linked to more than one user. That should not
          happen under normal use, but if it does you must reconcile those rows
          before migrating - it indicates a provider identity was linked to
          multiple accounts.
          """)
      end
    end

    defp find_resources_with_oauth2_strategies(igniter) do
      Igniter.Project.Module.find_all_matching_modules(igniter, fn _module, zipper ->
        case enter_auth_strategies(zipper) do
          {:ok, zipper} -> Enum.any?(@oauth2_family, &has_strategy?(zipper, &1))
          _ -> false
        end
      end)
    end

    defp ensure_identity_resource(resource, igniter) do
      identity_resource = conventional_identity_resource(resource)

      case Igniter.Project.Module.module_exists(igniter, identity_resource) do
        {true, igniter} ->
          Enum.reduce(
            @oauth2_family,
            igniter,
            &wire_identity_resource(&2, resource, &1, identity_resource)
          )

        {false, igniter} ->
          Igniter.add_warning(
            igniter,
            missing_identity_resource_warning(resource, identity_resource)
          )
      end
    end

    defp wire_identity_resource(igniter, resource, type, identity_resource) do
      case AshAuthentication.Igniter.defines_strategy_of_type(igniter, resource, type) do
        {igniter, true} ->
          igniter
          |> add_identity_resource_to_strategy(resource, type, identity_resource)
          |> ensure_register_action_has_identity_change(resource, type)

        {igniter, false} ->
          igniter
      end
    end

    defp conventional_identity_resource(resource) do
      resource
      |> Module.split()
      |> :lists.droplast()
      |> Enum.concat(["UserIdentity"])
      |> Module.concat()
    end

    defp add_identity_resource_to_strategy(igniter, resource, type, identity_resource) do
      Igniter.Project.Module.find_and_update_module!(igniter, resource, fn zipper ->
        with {:ok, zipper} <- enter_auth_strategies(zipper),
             {:ok, strategy_zipper} <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(zipper, type, [1, 2]),
             {:ok, do_block_zipper} <- Igniter.Code.Common.move_to_do_block(strategy_zipper),
             :error <-
               Igniter.Code.Function.move_to_function_call_in_current_scope(
                 do_block_zipper,
                 :identity_resource,
                 1
               ) do
          {:ok,
           Igniter.Code.Common.add_code(
             do_block_zipper,
             "identity_resource #{inspect(identity_resource)}"
           )}
        else
          _ -> {:ok, zipper}
        end
      end)
    end

    # sobelow_skip ["DOS.BinToAtom"]
    defp ensure_register_action_has_identity_change(igniter, resource, type) do
      action_name = :"register_with_#{type}"

      Igniter.Project.Module.find_and_update_module!(igniter, resource, fn zipper ->
        with {:ok, action_zipper} <- move_to_action(zipper, :create, action_name),
             {:ok, do_block_zipper} <- Igniter.Code.Common.move_to_do_block(action_zipper),
             false <- has_identity_change?(do_block_zipper) do
          {:ok,
           Igniter.Code.Common.add_code(
             do_block_zipper,
             "change AshAuthentication.Strategy.OAuth2.IdentityChange"
           )}
        else
          _ -> {:ok, zipper}
        end
      end)
    end

    defp has_identity_change?(zipper) do
      match?(
        {:ok, _},
        Igniter.Code.Function.move_to_function_call_in_current_scope(
          zipper,
          :change,
          1,
          fn change_zipper ->
            case Igniter.Code.Function.move_to_nth_argument(change_zipper, 0) do
              {:ok, arg_zipper} ->
                arg_zipper
                |> Sourceror.Zipper.node()
                |> Sourceror.to_string()
                |> String.contains?("IdentityChange")

              _ ->
                false
            end
          end
        )
      )
    end

    defp missing_identity_resource_warning(resource, identity_resource) do
      """
      #{inspect(resource)} has one or more OAuth2/OIDC strategies but no user
      identity resource could be found at #{inspect(identity_resource)}.

      As of this release, OAuth2 and OIDC strategies require an `identity_resource`.
      Matching a local user by their email address (or any other provider claim)
      is unsafe - only the provider's `iss`/`sub` claims uniquely and stably
      identify an end-user, and those are persisted in the identity resource.

      To resolve this manually:

        1. Create a user identity resource (conventionally #{inspect(identity_resource)}):

           defmodule #{inspect(identity_resource)} do
             use Ash.Resource,
               extensions: [AshAuthentication.UserIdentity],
               domain: <your domain>

             user_identity do
               user_resource #{inspect(resource)}
             end

             # ... data layer, postgres/sqlite block, etc.
           end

        2. Add `identity_resource #{inspect(identity_resource)}` to each OAuth2/OIDC
           strategy on #{inspect(resource)}.

        3. Add `change AshAuthentication.Strategy.OAuth2.IdentityChange` to each
           `register_with_*` action for those strategies.

      See the "User Identities" section of the strategy documentation for details.
      """
    end
  end
else
  defmodule Mix.Tasks.AshAuthentication.Upgrade do
    @moduledoc false

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'ash_authentication.upgrade' requires igniter. Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter/readme.html#installation
      """)

      exit({:shutdown, 1})
    end
  end
end
