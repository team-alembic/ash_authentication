defmodule AshAuthentication.Strategy.RememberMe.Token.Helpers do
  @moduledoc """
  Helpers for remember me tokens.
  """
  alias AshAuthentication.{Info, Jwt, TokenResource}

  def revoke_remember_me_token(token, otp_app, opts \\ []) do
    with {:ok, resource} <- Jwt.token_to_resource(token, otp_app),
         {:ok, token_resource} <- Info.authentication_tokens_token_resource(resource) do
      # we want this to blow up if something goes wrong
      :ok = TokenResource.Actions.revoke(token_resource, token, opts)
    end
  end
end
