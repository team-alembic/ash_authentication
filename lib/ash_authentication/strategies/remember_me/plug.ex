defmodule AshAuthentication.Strategy.RememberMe.Plug do
  @moduledoc """
  Plug for signing in with remember me.
  """

  alias Ash.Query
  alias AshAuthentication.{Info, Strategy.RememberMe, Plug.Helpers}

  @doc """
  Sign in the given Ash Resource with the AshAuthentication RememberMe strategy.

  For the given resource, find the remember me strategies.

  If no remember me strategies are found, do nothing.

  If a remember me strategy is found, but no token is found, do nothing.

  If a remember me strategy is found, and a token is found in the cookies, 
  and the token is valid, login the user.

  If a remember me strategy is found, and a token is found in the cookies, 
  and the token is invalid, delete the cookie.
  """
  @spec sign_in_resource_with_remember_me(Plug.Conn.t(), Ash.Resource.t(), Keyword.t()) ::
          Plug.Conn.t()
  def sign_in_with_remember_me(conn, resource, _opts) do
    action_options = Keyword.new()

    action_options =
      action_options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(resource) end)

    resource
    |> Info.authentication_strategies()
    |> Enum.reduce(conn, fn strategy, conn ->
      case strategy do
        %RememberMe{cookie_name: cookie_name} ->
          full_cookie_name = RememberMe.Cookie.cookie_name(cookie_name)

          conn
          |> Plug.Conn.get_cookies()
          |> Map.get(full_cookie_name)
          |> case do
            nil ->
              conn

            token ->
              resource
              |> Query.new()
              |> Query.set_context(%{
                private: %{ash_authentication?: true},
                strategy_name: strategy
              })
              |> Query.for_read(:sign_in_with_remember_me, %{token: token}, action_options)
              |> Ash.read_one()
              |> case do
                {:ok, user} ->
                  Helpers.store_in_session(conn, user)

                {:error, _reason} ->
                  # Cookie is invalid, delete it
                  Plug.Conn.delete_resp_cookies(conn, full_cookie_name)
              end
          end

        _ ->
          conn
      end
    end)
  end
end
