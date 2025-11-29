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
          "4.14.0" => [&fix_google_hd_field/2],
          "5.0.0" => [&convert_revoked_read_action_to_generic/2]
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

    @doc """
    Fixes the Google strategy field name change from "google_hd" to "hd".

    The Google strategy now uses OIDC which returns standard
    claims. The hosted domain claim changed from "google_hd" to "hd".
    """
    def fix_google_hd_field(igniter, _opts) do
      igniter
      |> replace_google_hd_strings()
      |> Igniter.add_notice("""
      Google Strategy Breaking Change:

      The `email_verified` field in `user_info` is now a `boolean` instead of a `string`.

      If your code checks `user_info["email_verified"] == "true"`, update it to:
        user_info["email_verified"] == true

      Please review your `register_with_google` action and any code that accesses
      the `email_verified` field from Google OAuth responses.
      """)
    end

    defp replace_google_hd_strings(igniter) do
      igniter = Igniter.include_all_elixir_files(igniter)

      igniter.rewrite
      |> Rewrite.sources()
      |> Enum.filter(&match?(%Rewrite.Source{filetype: %Rewrite.Source.Ex{}}, &1))
      |> Enum.reduce(igniter, fn source, igniter ->
        zipper =
          source
          |> Rewrite.Source.get(:quoted)
          |> Sourceror.Zipper.zip()

        case replace_google_hd_in_zipper(zipper) do
          {:ok, new_zipper} ->
            new_quoted = Sourceror.Zipper.topmost_root(new_zipper)
            new_source = Igniter.update_source(source, igniter, :quoted, new_quoted)
            %{igniter | rewrite: Rewrite.update!(igniter.rewrite, new_source)}

          :unchanged ->
            igniter
        end
      end)
    end

    defp replace_google_hd_in_zipper(zipper) do
      {new_zipper, changed?} =
        Sourceror.Zipper.traverse(zipper, false, fn zipper, changed? ->
          if google_hd_string?(zipper) do
            {replace_with_hd(zipper), true}
          else
            {zipper, changed?}
          end
        end)

      if changed? do
        {:ok, new_zipper}
      else
        :unchanged
      end
    end

    defp google_hd_string?(%{node: "google_hd"}), do: true

    defp google_hd_string?(%{node: {:__block__, meta, ["google_hd"]}}) when is_list(meta),
      do: true

    defp google_hd_string?(_), do: false

    defp replace_with_hd(%{node: "google_hd"} = zipper) do
      Sourceror.Zipper.replace(zipper, "hd")
    end

    defp replace_with_hd(%{node: {:__block__, meta, ["google_hd"]}} = zipper) do
      Sourceror.Zipper.replace(zipper, {:__block__, meta, ["hd"]})
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

    def convert_revoked_read_action_to_generic(igniter, _opts) do
      case find_all_token_resources(igniter) do
        {igniter, []} ->
          igniter

        {igniter, resources} ->
          Enum.reduce(resources, igniter, fn resource, igniter ->
            maybe_convert_revoked_read_to_generic(igniter, resource)
          end)
      end
    end

    defp maybe_convert_revoked_read_to_generic(igniter, resource) do
      Igniter.Project.Module.find_and_update_module!(igniter, resource, fn zipper ->
        with {:ok, action_zipper} <- move_to_action(zipper, :read, :revoked?),
             {:ok, do_block_zipper} <- Igniter.Code.Common.move_to_do_block(action_zipper) do
          convert_read_to_generic_action(do_block_zipper)
        else
          :error -> {:ok, zipper}
        end
      end)
    end

    defp convert_read_to_generic_action(do_block_zipper) do
      do_block_zipper =
        Igniter.Code.Common.remove(
          do_block_zipper,
          &Igniter.Code.Function.function_call?(&1, :get?, 1)
        )

      do_block_zipper =
        Igniter.Code.Common.remove(
          do_block_zipper,
          &Igniter.Code.Function.function_call?(&1, :prepare, 1)
        )

      do_block_zipper =
        Igniter.Code.Common.add_code(
          do_block_zipper,
          "run AshAuthentication.TokenResource.IsRevoked"
        )

      zipper = Sourceror.Zipper.top(do_block_zipper)

      with {:ok, zipper} <- move_to_action(zipper, :read, :revoked?) do
        new_node =
          Sourceror.Zipper.node(zipper)
          |> replace_read_with_action()
          |> insert_boolean_return_type()

        {:ok, Sourceror.Zipper.replace(zipper, new_node)}
      end
    end

    defp replace_read_with_action({:read, meta, args}) do
      {:action, meta, args}
    end

    defp insert_boolean_return_type({:action, meta, [name | rest]}) do
      {:action, meta, [name, :boolean | rest]}
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
