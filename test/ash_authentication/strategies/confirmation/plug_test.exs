defmodule AshAuthentication.Strategy.Confirmation.PlugTest do
  @moduledoc false
  use DataCase, async: true
  import Plug.Test

  alias Ash.Changeset

  alias AshAuthentication.{
    Info,
    Plug.Helpers,
    Strategy.Confirmation,
    Strategy.Confirmation.Plug
  }

  describe "confirm/2" do
    test "it returns an error when there is no corresponding user" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()

      {:ok, token} =
        Confirmation.confirmation_token(
          strategy,
          Changeset.for_update(user, :update, %{"username" => username()})
        )

      Example.Repo.delete!(user)

      params = %{
        "confirm" => token
      }

      assert {_conn, {:error, error}} =
               :get
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
               :get
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
          Changeset.for_update(user, :update, %{"username" => username()})
        )

      params = %{
        "confirm" => token
      }

      assert {_conn, {:ok, confirmed_user}} =
               :get
               |> conn("/", params)
               |> Plug.confirm(strategy)
               |> Helpers.get_authentication_result()

      assert confirmed_user.confirmed_at
    end
  end
end
