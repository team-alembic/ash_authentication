# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RememberMe.Plug.Helpers do
  @moduledoc """
  Plug for signing in with remember me token in cookies.
  """

  alias Ash.{Query, Resource}
  alias AshAuthentication.{Info, Strategy.RememberMe}
  alias Plug.Conn

  import AshAuthentication.Strategy.RememberMe.Token.Helpers

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
          Plug.Conn.t() | {Plug.Conn.t(), Resource.record()}
  def sign_in_resource_with_remember_me(%{cookies: %Plug.Conn.Unfetched{}} = conn, resource, opts) do
    sign_in_resource_with_remember_me(Conn.fetch_cookies(conn), resource, opts)
  end

  def sign_in_resource_with_remember_me(conn, resource, _opts) do
    conn = Conn.fetch_cookies(conn)

    resource
    |> Info.authentication_strategies()
    |> Enum.reduce(conn, fn strategy, conn ->
      attempt_sign_in_resource_with_remember_me(conn, resource, strategy)
    end)
  end

  @doc false
  defp attempt_sign_in_resource_with_remember_me(
         conn,
         resource,
         %RememberMe{cookie_name: cookie_name} = strategy
       ) do
    cookie_name = to_string(cookie_name)

    conn
    |> Plug.Conn.get_cookies()
    |> Map.get(cookie_name)
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
        |> Query.for_read(strategy.sign_in_action_name, %{token: token},
          domain: Info.domain!(resource)
        )
        |> Ash.read_one()
        |> case do
          {:ok, user} ->
            {conn, user}

          {:error, _reason} ->
            # Cookie is invalid, delete it
            Plug.Conn.delete_resp_cookie(conn, cookie_name)
        end
    end
  end

  defp attempt_sign_in_resource_with_remember_me(conn, _resource, _strategy), do: conn

  @remember_me_cookie_options [
    # cookie is only readable by HTTP/S
    http_only: true,
    # only send the cookie over HTTPS, except in development
    # otherwise Safari will block the cookie
    secure: Mix.env() != :dev,
    # prevents the cookie from being sent with cross-site requests
    same_site: "Lax"
  ]

  @doc """
  Put the remember me token in connection response cookies.
  """
  @spec put_remember_me_cookie(Conn.t(), String.t(), map) :: Conn.t()
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
  Get all the remember me cookie names for the given otp_app.
  """
  @spec all_remember_me_cookie_names(atom) :: [String.t()]
  def all_remember_me_cookie_names(otp_app) do
    otp_app
    |> AshAuthentication.authenticated_resources()
    |> Enum.flat_map(fn resource ->
      Info.authentication_strategies(resource)
    end)
    |> Enum.reduce([], fn strategy, acc ->
      case strategy do
        %RememberMe{cookie_name: cookie_name} -> acc ++ [to_string(cookie_name)]
        _ -> acc
      end
    end)
  end

  @doc """
  Delete all the remember me tokens from the response cookies.
  """
  @spec delete_all_remember_me_cookies(Conn.t(), atom) :: Conn.t()
  def delete_all_remember_me_cookies(%{cookies: %Plug.Conn.Unfetched{}} = conn, otp_app) do
    delete_all_remember_me_cookies(Conn.fetch_cookies(conn), otp_app)
  end

  def delete_all_remember_me_cookies(conn, otp_app) do
    otp_app
    |> all_remember_me_cookie_names()
    |> Enum.reduce(conn, fn cookie_name, conn ->
      token = Plug.Conn.get_cookies(conn) |> Map.get(cookie_name)

      case token do
        nil ->
          conn

        token ->
          opts =
            []
            |> Keyword.put_new(:tenant, Ash.PlugHelpers.get_tenant(conn))
            |> Keyword.put_new(:context, Ash.PlugHelpers.get_context(conn) || %{})

          revoke_remember_me_token(token, otp_app, opts)
          delete_remember_me_cookie(conn, cookie_name)
      end

      delete_remember_me_cookie(conn, cookie_name)
    end)
  end

  @doc """
  Take a connection and possibly an authentication result tuple, call the endpoint
  to put the remember me cookie
  """
  @spec maybe_put_remember_me_cookies({Plug.Conn.t(), any} | Plug.Conn.t(), any) ::
          {Plug.Conn.t(), any} | Plug.Conn.t()
  def maybe_put_remember_me_cookies({conn, {:ok, user} = result}, return_to)
      when is_map(user.__metadata__.remember_me) do
    remember_me = user.__metadata__.remember_me
    cookie_name = to_string(remember_me.cookie_name)

    conn =
      conn
      |> return_to.put_remember_me_cookie(cookie_name, remember_me)

    {conn, result}
  end

  def maybe_put_remember_me_cookies(conn_with_auth_result, _return_to), do: conn_with_auth_result
end
