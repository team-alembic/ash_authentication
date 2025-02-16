defmodule AshAuthentication.TokenResource.ExpungerTest do
  @moduledoc false
  use DataCase, async: false
  alias AshAuthentication.{Jwt, TokenResource.Expunger}

  describe "init/1" do
    test "it finds all token resources to expunge" do
      assert {:ok, %{otp_app: :ash_authentication, resources: resource_states}} =
               Expunger.init(otp_app: :ash_authentication)

      assert %{Example.Token => %{timer: timer, interval: interval}} = resource_states
      assert timer
      assert is_integer(interval) and interval > 0
    end
  end

  describe "handle_info/2" do
    test "it removes expired tokens from the resource" do
      {:ok, state} = Expunger.init(otp_app: :ash_authentication)
      user = build_user()

      Example.Token
      |> Ash.Query.for_read(:read)
      |> Ash.bulk_destroy!(:destroy, %{}, authorize?: false)

      now =
        DateTime.utc_now()
        |> DateTime.to_unix()

      alive =
        Enum.flat_map(10..-10//-2, fn
          0 ->
            []

          i ->
            {:ok, _, claims} = Jwt.token_for_user(user, %{"exp" => now + i})
            [claims]
        end)
        |> Enum.filter(&(&1["exp"] >= now))
        |> MapSet.new(&{&1["jti"], &1["exp"] - now})

      Expunger.handle_info({:expunge, Example.Token}, state)

      assert {:ok, remaining} = Ash.read(Example.Token, authorize?: false)
      remaining = MapSet.new(remaining, &{&1.jti, DateTime.to_unix(&1.expires_at) - now})

      assert MapSet.equal?(remaining, alive)
    end
  end
end
