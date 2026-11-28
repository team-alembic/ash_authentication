# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RememberMe.Token.Helpers do
  @moduledoc """
  Helpers for remember me tokens.
  """
  alias AshAuthentication.{Info, Jwt, TokenResource}

  @doc """
  Revokes a remember me token.

  Takes the otp app whose authenticated resources the token may belong to, or
  a list of those resources. Returns `:error` when the token does not verify,
  or when it maps to no authentication resource.
  """
  @spec revoke_remember_me_token(String.t(), atom | [Ash.Resource.t()], keyword) ::
          :ok | :error | {:error, any}
  def revoke_remember_me_token(token, otp_app_or_resources, opts \\ [])
  def revoke_remember_me_token(nil, _otp_app_or_resources, _opts), do: :ok

  def revoke_remember_me_token(token, otp_app_or_resources, opts) do
    with {:ok, _claims, resource} <- Jwt.verify(to_string(token), otp_app_or_resources, opts),
         {:ok, token_resource} <- Info.authentication_tokens_token_resource(resource) do
      store_all_tokens? = Info.authentication_tokens_store_all_tokens?(resource)
      opts = Keyword.put(opts, :store_all_tokens?, store_all_tokens?)

      TokenResource.Actions.revoke(token_resource, token, opts)
    else
      :error -> :error
    end
  end
end
