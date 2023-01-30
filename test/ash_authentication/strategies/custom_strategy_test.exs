defmodule AshAuthentication.Strategy.CustomStrategyTest do
  @moduledoc false
  use DataCase
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Plug.Helpers, Strategy}
  import Plug.Test

  test "when an existing user whose username doesn't start with \"marty\", they can't sign in" do
    strategy = Info.strategy!(Example.User, :marty)
    build_user(username: "doc_brown")

    conn = conn(:post, "/user/marty", %{"username" => "doc_brown"})

    {_conn, {:error, error}} =
      strategy
      |> Strategy.plug(:sign_in, conn)
      |> Helpers.get_authentication_result()

    assert %AuthenticationFailed{caused_by: %{reason: :no_user}} = error
  end

  test "when not an existing user, they can't sign in" do
    strategy = Info.strategy!(Example.User, :marty)

    conn = conn(:post, "/user/marty", %{"username" => username()})

    {_conn, {:error, error}} =
      strategy
      |> Strategy.plug(:sign_in, conn)
      |> Helpers.get_authentication_result()

    assert %AuthenticationFailed{caused_by: %{reason: :no_user}} = error
  end

  test "when an existing user whose username starts with \"marty\", they can sign in" do
    strategy = Info.strategy!(Example.User, :marty)
    user0 = build_user(username: "marty_mcfly")

    conn = conn(:post, "/user/marty", %{"username" => "marty_mcfly"})

    {_conn, {:ok, user1}} =
      strategy
      |> Strategy.plug(:sign_in, conn)
      |> Helpers.get_authentication_result()

    assert user0.id == user1.id
  end
end
