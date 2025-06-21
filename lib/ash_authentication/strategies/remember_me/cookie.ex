defmodule AshAuthentication.Strategy.RememberMe.Cookie do
  @moduledoc """
  Helper functions for working with remember me cookies.
  """

  @cookie_name_prefix "ash_auth:remember_me"

  @doc """
  Generate a cookie name for a given resource. All cookie names are begin with
  "ash_auth:remember_me" for identifying remember me cookies in the connection.
  """
  @spec cookie_name(Ash.Resource.t()) :: String.t()
  def cookie_name(:remember_me), do: @cookie_name_prefix
  def cookie_name("remember_me"), do: @cookie_name_prefix

  def cookie_name(strategy_cookie_name) do
    @cookie_name_prefix <> ":" <> to_string(strategy_cookie_name)
  end

  def prefix(), do: @cookie_name_prefix
end
