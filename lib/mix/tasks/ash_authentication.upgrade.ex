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
          "4.14.0" => [&fix_google_hd_field/2]
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
