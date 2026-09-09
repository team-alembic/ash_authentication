# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.UserIdentity.Verifier do
  @moduledoc """
  The user identity verifier.
  """

  use Spark.Dsl.Transformer
  alias Ash.Resource
  alias AshAuthentication.UserIdentity.Info
  alias Spark.Dsl.Transformer
  import AshAuthentication.Utils

  @doc false
  @impl true
  @spec after?(any) :: boolean()
  def after?(_), do: true

  @doc false
  @impl true
  @spec before?(any) :: boolean
  def before?(_), do: false

  @doc false
  @impl true
  @spec after_compile? :: boolean
  def after_compile?, do: true

  @doc false
  @impl true
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with :ok <- validate_domain_presence(dsl_state),
         :ok <- validate_user_resource(dsl_state) do
      case token_sensitivity_warnings(dsl_state) do
        [] -> :ok
        warnings -> {:warn, dsl_state, warnings}
      end
    end
  end

  defp validate_domain_presence(dsl_state) do
    with {:ok, domain} <- Info.user_identity_domain(dsl_state) do
      assert_is_domain(domain)
    end
  end

  defp validate_user_resource(dsl_state) do
    with {:ok, user_resource} <- Info.user_identity_user_resource(dsl_state) do
      assert_resource_has_extension(user_resource, AshAuthentication)
    end
  end

  # The provider's access and refresh tokens are bearer credentials, so they
  # must be marked `sensitive?: true`. Anything which reads the flag as a
  # credential classification - the audit log add-on, the `Inspect` protocol -
  # otherwise treats them as safe to display and to persist. The transformer
  # sets the flag on the fields it builds; a hand-written resource is only
  # warned about, because a hard error would break existing applications on a
  # patch release.
  defp token_sensitivity_warnings(dsl_state) do
    with {:ok, access_token} <- Info.user_identity_access_token_attribute_name(dsl_state),
         {:ok, refresh_token} <- Info.user_identity_refresh_token_attribute_name(dsl_state) do
      [
        attribute_sensitivity_warning(dsl_state, access_token),
        attribute_sensitivity_warning(dsl_state, refresh_token),
        upsert_argument_sensitivity_warning(dsl_state)
      ]
      |> Enum.reject(&is_nil/1)
    else
      _ -> []
    end
  end

  defp attribute_sensitivity_warning(dsl_state, field_name) do
    with attribute when is_map(attribute) <- Resource.Info.attribute(dsl_state, field_name),
         false <- attribute.sensitive? do
      """
      The `#{inspect(field_name)}` attribute on `#{inspect(resource(dsl_state))}` is not marked `sensitive?: true`.

      It holds a bearer credential issued by the identity provider. Without the
      flag the value appears in `inspect/1` output and in crash reports, and the
      audit log add-on treats it as safe to persist. Add `sensitive?: true` to
      the attribute. This will become a hard requirement in a future release.
      """
    else
      _ -> nil
    end
  end

  defp upsert_argument_sensitivity_warning(dsl_state) do
    with {:ok, action_name} <- Info.user_identity_upsert_action_name(dsl_state),
         action when is_map(action) <- Resource.Info.action(dsl_state, action_name),
         argument when is_map(argument) <-
           Enum.find(action.arguments, &(&1.name == :oauth_tokens)),
         false <- argument.sensitive? do
      """
      The `:oauth_tokens` argument on the `#{inspect(action_name)}` action of `#{inspect(resource(dsl_state))}` is not marked `sensitive?: true`.

      It carries the identity provider's whole token response, including the
      access and refresh tokens. Without the flag the audit log add-on records
      the tokens in plain text and they appear in `inspect/1` output. Add
      `sensitive?: true` to the argument. This will become a hard requirement in
      a future release.
      """
    else
      _ -> nil
    end
  end

  defp resource(dsl_state), do: Transformer.get_persisted(dsl_state, :module)
end
