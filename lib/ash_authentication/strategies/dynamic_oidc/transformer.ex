# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.DynamicOidc.Transformer do
  @moduledoc """
  DSL transformer for `dynamic_oidc` strategies.

  Replaces `nonce: true` with the default `NonceGenerator` (mirroring OIDC),
  then defers to the OAuth2 transformer for register/sign-in action defaults,
  identity-relationship setup, and action validation.
  """

  alias AshAuthentication.Strategy.{DynamicOidc, OAuth2, Oidc.NonceGenerator}

  @doc false
  @spec transform(DynamicOidc.t(), map) ::
          {:ok, DynamicOidc.t() | map} | {:error, Exception.t()}
  def transform(strategy, dsl_state) do
    strategy
    |> maybe_install_default_nonce_generator()
    |> OAuth2.transform(dsl_state)
  end

  defp maybe_install_default_nonce_generator(%{nonce: true} = strategy),
    do: %{strategy | nonce: {NonceGenerator, []}}

  defp maybe_install_default_nonce_generator(strategy), do: strategy
end
