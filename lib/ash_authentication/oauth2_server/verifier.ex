# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.RefreshTokenResource do
  @moduledoc """
  Marker extension for an OAuth 2.1 refresh-token resource.

  Registers `AshAuthentication.Oauth2Server.RefreshTokenResource.Verifier`,
  which checks at compile time that the resource conforms to the contract
  the `Token` core depends on for race-safe rotation.

  Add to your refresh-token resource:

      use Ash.Resource,
        extensions: [AshAuthentication.Oauth2Server.RefreshTokenResource],
        ...
  """

  use Spark.Dsl.Extension,
    verifiers: [AshAuthentication.Oauth2Server.RefreshTokenResource.Verifier]
end

defmodule AshAuthentication.Oauth2Server.RefreshTokenResource.Verifier do
  @moduledoc """
  Verifies the refresh-token resource has the shape the Token core
  depends on:

    * `:id` attribute is writable (the library pre-allocates the new
      refresh row's id so a rotation is one filtered UPDATE).
    * `:rotate` action exists and carries a filter expression (filters
      already-rotated / already-revoked rows out of the underlying
      UPDATE; race-safety lives entirely here).

  Violations raise at resource-compile time with a fix-it message.
  """

  use Spark.Dsl.Verifier

  alias Spark.{Dsl.Verifier, Error.DslError}

  @impl true
  def verify(dsl_state) do
    with :ok <- verify_id_writable(dsl_state) do
      verify_rotate_action(dsl_state)
    end
  end

  defp verify_id_writable(dsl_state) do
    case attribute(dsl_state, :id) do
      %{writable?: true} ->
        :ok

      %{writable?: false} ->
        {:error,
         DslError.exception(
           module: Verifier.get_persisted(dsl_state, :module),
           path: [:attributes, :id],
           message: """
           The OAuth2 refresh-token resource needs a writable `:id` attribute.

           The Token core pre-allocates the new refresh row's id so the
           rotation can be a single filtered UPDATE; with a non-writable
           `:id` it can't be set explicitly.

           Fix: declare `:id` like this (instead of `uuid_v7_primary_key :id`):

               attribute :id, :uuid_v7 do
                 primary_key? true
                 allow_nil? false
                 default &Ash.UUIDv7.generate/0
                 writable? true
                 public? true
               end
           """
         )}

      nil ->
        {:error,
         DslError.exception(
           module: Verifier.get_persisted(dsl_state, :module),
           path: [:attributes],
           message: "The OAuth2 refresh-token resource must declare a writable `:id` primary key."
         )}
    end
  end

  @rotate_change AshAuthentication.Oauth2Server.Changes.RotateRefreshToken

  defp verify_rotate_action(dsl_state) do
    case action(dsl_state, :rotate) do
      nil ->
        {:error,
         DslError.exception(
           module: Verifier.get_persisted(dsl_state, :module),
           path: [:actions],
           message:
             "The OAuth2 refresh-token resource must declare a `:rotate` update action. " <>
               "Re-run `mix ash_authentication.add_oauth2_server` or copy the action from the installer's scaffold."
         )}

      %{type: :update} = action ->
        if has_rotate_change?(action) do
          :ok
        else
          {:error, rotate_missing_change_error(dsl_state)}
        end

      other ->
        {:error,
         DslError.exception(
           module: Verifier.get_persisted(dsl_state, :module),
           path: [:actions, :rotate],
           message:
             "The `:rotate` action must be an `update` action (got #{inspect(other.type)})."
         )}
    end
  end

  # The change module attaches the atomic filter AND sets the
  # rotated_to_id attribute. Presence of the change is the contract.
  defp has_rotate_change?(%{changes: changes}) when is_list(changes) do
    Enum.any?(changes, fn
      %{change: {mod, _opts}} -> mod == @rotate_change
      %{change: mod} when is_atom(mod) -> mod == @rotate_change
      _ -> false
    end)
  end

  defp has_rotate_change?(_), do: false

  defp rotate_missing_change_error(dsl_state) do
    DslError.exception(
      module: Verifier.get_persisted(dsl_state, :module),
      path: [:actions, :rotate],
      message: """
      The `:rotate` action must include the
      `#{inspect(@rotate_change)}` change.

      That change attaches the atomic filter and sets the
      `:rotated_to_id` attribute together — without it, two concurrent
      refresh-token requests can both succeed and issue two new tokens
      for the same refresh, defeating reuse detection.

      Fix:

          update :rotate do
            argument :rotated_to_id, :uuid_v7, allow_nil?: false
            accept []
            require_atomic? false

            change #{inspect(@rotate_change)}
          end
      """
    )
  end

  defp attribute(dsl_state, name) do
    dsl_state
    |> Verifier.get_entities([:attributes])
    |> Enum.find(&(&1.name == name))
  end

  defp action(dsl_state, name) do
    dsl_state
    |> Verifier.get_entities([:actions])
    |> Enum.find(&(&1.name == name))
  end
end
