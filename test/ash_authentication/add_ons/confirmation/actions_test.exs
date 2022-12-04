defmodule AshAuthentication.AddOn.Confirmation.ActionsTest do
  @moduledoc false
  use DataCase, async: true

  import Ecto.Query

  alias Ash.Changeset
  alias AshAuthentication.{AddOn.Confirmation, AddOn.Confirmation.Actions, Info, Jwt}

  describe "confirm/2" do
    test "it returns an error when there is no corresponding user" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()

      changeset =
        user
        |> Changeset.for_update(:update, %{"username" => username()})

      {:ok, token} = Confirmation.confirmation_token(strategy, changeset)

      Example.Repo.delete!(user)

      assert {:error, error} = Actions.confirm(strategy, %{"confirm" => token}, [])
      assert Exception.message(error) == "record not found"
    end

    test "it returns an error when the token is invalid" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)

      assert {:error, error} = Actions.confirm(strategy, %{"confirm" => Ecto.UUID.generate()}, [])
      assert Exception.message(error) == "Invalid confirmation token"
    end

    test "it updates the confirmed_at field" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()
      new_username = username()

      changeset =
        user
        |> Changeset.for_update(:update, %{"username" => new_username})

      {:ok, token} = Confirmation.confirmation_token(strategy, changeset)

      assert {:ok, confirmed_user} = Actions.confirm(strategy, %{"confirm" => token}, [])

      assert confirmed_user.id == user.id
      assert to_string(confirmed_user.username) == new_username

      assert_in_delta DateTime.to_unix(confirmed_user.confirmed_at),
                      DateTime.to_unix(DateTime.utc_now()),
                      1.0
    end
  end

  describe "store_changes/3" do
    test "it stores only the changes in the strategy's monitored fields" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()

      changeset =
        user
        |> Changeset.for_update(:update, %{
          "username" => username(),
          "hashed_password" => password()
        })

      {:ok, token, _} = Jwt.token_for_user(user)

      :ok = Actions.store_changes(strategy, token, changeset)

      query =
        from(t in Example.Token,
          where: t.purpose == "confirm",
          order_by: [desc: t.created_at],
          limit: 1
        )

      token = Example.Repo.one(query)

      assert Map.has_key?(token.extra_data, "username")
      refute Map.has_key?(token.extra_data, "hashed_password")
    end
  end

  describe "get_changes/2" do
    test "it retrieves only the changes in the strategy's monitored fields" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()

      {:ok, _token, %{"jti" => jti, "exp" => exp}} = Jwt.token_for_user(user)

      %Example.Token{}
      |> Ecto.Changeset.cast(
        %{
          "jti" => jti,
          "expires_at" => DateTime.from_unix!(exp),
          "purpose" => "confirm",
          "extra_data" => %{"username" => username(), "hashed_password" => password()}
        },
        ~w[jti expires_at purpose extra_data]a
      )
      |> Example.Repo.insert!()

      {:ok, changes} = Actions.get_changes(strategy, jti)

      assert Map.has_key?(changes, "username")
      refute Map.has_key?(changes, "hashed_password")
    end
  end
end
