defmodule AshAuthentication.Strategy.RememberMe.Token.Helpers do
  @moduledoc """
  Helpers for remember me tokens.
  """
  alias AshAuthentication.{Info, Jwt, TokenResource}

  @doc """
  Revokes a remember me token.
  """
  @spec revoke_remember_me_token(String.t(), atom, keyword) :: :ok | {:error, any}
  def revoke_remember_me_token(token, otp_app, opts \\ []) do
    with {:ok, resource} <- Jwt.token_to_resource(token, otp_app),
         {:ok, token_resource} <- Info.authentication_tokens_token_resource(resource) do
      TokenResource.Actions.revoke(token_resource, token, opts)
    end
  end
end
