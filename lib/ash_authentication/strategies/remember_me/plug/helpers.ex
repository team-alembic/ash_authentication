defmodule AshAuthentication.Strategy.RememberMe.Plug.Helpers do
  @moduledoc """
  Plug for signing in with remember me token in cookies.
  """

  alias Ash.Query
  alias AshAuthentication.{Info, Strategy.RememberMe}
  alias Plug.Conn

  @doc """
  Sign in the given Ash Resource with the AshAuthentication RememberMe strategy.
  To sign in with any Ash Resource see sign_in_resource_with_remember_me.

  For the given resource, find the remember me strategies.

  If no remember me strategies are found, do nothing.

  If a remember me strategy is found, but no token is found, do nothing.

  If a remember me strategy is found, and a token is found in the cookies, 
  and the token is valid, login the user.

  If a remember me strategy is found, and a token is found in the cookies, 
  and the token is invalid, delete the cookie.
  """
  @spec sign_in_resource_with_remember_me(Plug.Conn.t(), Ash.Resource.t(), Keyword.t()) ::
          Plug.Conn.t() | {Plug.Conn.t(), Ash.Resouce.t()}
  def sign_in_resource_with_remember_me(conn, resource, _opts) do
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
                  {:conn, user}

                {:error, _reason} ->
                  # Cookie is invalid, delete it
                  Plug.Conn.delete_resp_cookie(conn, full_cookie_name)
              end
          end

        _ ->
          conn
      end
    end)
  end

  @remember_me_cookie_options [
    # prevents the cookie from being accessed by JavaScript
    http_only: true,
    # only send the cookie over HTTPS
    secure: true,
    # prevents the cookie from being sent with cross-site requests
    same_site: "Lax"
  ]

  @doc """
  Put the remember me token in connection response cookies.
  """
  @spec put_remember_me_cookie(Conn.t(), String.t(), Map.t()) :: Conn.t()
  def put_remember_me_cookie(conn, cookie_name, %{token: token, max_age: max_age}) do
    cookie_options = Keyword.put(@remember_me_cookie_options, :max_age, max_age)

    conn
    |> Conn.put_resp_cookie(cookie_name, token, cookie_options)
  end

  @doc """
  Delete the remember me token from the connection response cookies.
  """
  @spec delete_remember_me_cookie(Conn.t(), String.t()) :: Conn.t()
  def delete_remember_me_cookie(conn, cookie_name) do
    cookie_options = Keyword.put(@remember_me_cookie_options, :max_age, 0)

    conn
    |> Conn.delete_resp_cookie(cookie_name, cookie_options)
  end

  @doc """
  Delete all the remember me tokens from the response cookies.
  """
  @spec delete_all_remember_me_cookies(Conn.t()) :: Conn.t()
  def delete_all_remember_me_cookies(conn) do
    conn
    |> Conn.get_cookies()
    |> Enum.reduce(conn, fn {key, _}, conn ->
      if String.starts_with?(key, AshAuthentication.Strategy.RememberMe.Cookie.prefix()) do
        delete_remember_me_cookie(conn, key)
      else
        conn
      end
    end)
  end
end
