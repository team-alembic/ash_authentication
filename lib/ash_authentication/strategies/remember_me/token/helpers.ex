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
  """
  @spec revoke_remember_me_token(String.t(), atom, keyword) :: :ok | {:error, any}
  def revoke_remember_me_token(token, otp_app, opts \\ [])
  def revoke_remember_me_token(nil, _otp_app, _opts), do: :ok

  def revoke_remember_me_token(token, otp_app, opts) do
    with {:ok, resource} <- Jwt.token_to_resource(to_string(token), otp_app),
         {:ok, token_resource} <- Info.authentication_tokens_token_resource(resource) do
      :ok = TokenResource.Actions.revoke(token_resource, token, opts)
    else
      :error -> :error
    end
  end
end
