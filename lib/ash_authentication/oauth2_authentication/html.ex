defmodule AshAuthentication.OAuth2Authentication.Html do
  @moduledoc """
  Renders a very basic sign-in button.
  """

  require EEx
  alias AshAuthentication.OAuth2Authentication, as: OAuth2

  EEx.function_from_string(
    :defp,
    :render,
    ~s"""
      <a href="<%= @action %>"><%= @legend %></a>
    """,
    [:assigns]
  )

  @doc false
  @spec callback(module, keyword) :: String.t()
  def callback(_, _), do: ""

  @doc false
  @spec request(module, keyword) :: String.t()
  def request(resource, options) do
    options
    |> Map.new()
    |> Map.merge(OAuth2.Info.options(resource))
    |> Map.merge(AshAuthentication.Info.authentication_options(resource))
    |> Map.put_new(:legend, "Sign in with #{OAuth2.provides(resource)}")
    |> render()
  end
end
