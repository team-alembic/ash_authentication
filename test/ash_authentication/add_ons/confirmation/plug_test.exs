# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.Confirmation.PlugTest do
  @moduledoc false
  use DataCase, async: true
  import Plug.Test

  alias Ash.Changeset

  alias AshAuthentication.{
    AddOn.Confirmation,
    AddOn.Confirmation.Plug,
    Info,
    Plug.Helpers
  }

  describe "confirm/2" do
    test "it returns an error when there is no corresponding user" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()

      {:ok, token} =
        Confirmation.confirmation_token(
          strategy,
          Changeset.for_update(user, :update, %{"username" => username()}),
          user
        )

      Example.Repo.delete!(user)

      params = %{
        "confirm" => token
      }

      assert {_conn, {:error, error}} =
               :post
               |> conn("/", params)
               |> Plug.confirm(strategy)
               |> Helpers.get_authentication_result()

      assert Exception.message(error) == "record not found"
    end

    test "it returns an error when the token is invalid" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)

      params = %{
        "confirm" => Ecto.UUID.generate()
      }

      assert {_conn, {:error, error}} =
               :post
               |> conn("/", params)
               |> Plug.confirm(strategy)
               |> Helpers.get_authentication_result()

      assert Exception.message(error) == "Invalid confirmation token"
    end

    test "it returns a successful result" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()

      refute user.confirmed_at

      {:ok, token} =
        Confirmation.confirmation_token(
          strategy,
          Changeset.for_update(user, :update, %{"username" => username()}),
          user
        )

      params = %{
        "confirm" => token
      }

      assert {_conn, {:ok, confirmed_user}} =
               :post
               |> conn("/", params)
               |> Plug.confirm(strategy)
               |> Helpers.get_authentication_result()

      assert confirmed_user.confirmed_at
    end
  end

  describe "accept/2" do
    test "it HTML-escapes the token into the rendered form" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)

      payload = ~s|"><script>alert(1)</script>|

      conn =
        :get
        |> conn("/", %{"confirm" => payload})
        |> Plug.accept(strategy)

      assert conn.status == 200

      refute conn.resp_body =~ payload
      refute conn.resp_body =~ "<script>"

      assert conn.resp_body =~
               ~s|value="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"|
    end
  end
end
