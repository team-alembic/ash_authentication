defmodule AshAuthentication.AddOns.LogOutEverywhereTest do
  @moduledoc false
  use DataCase, async: false
  alias AshAuthentication.{Info, Jwt, Strategy, TokenResource}

  describe "log_out_everywhere action" do
    test "all existing tokens for a user a revoked" do
      user = build_user_with_token_required()
      strategy = Info.strategy!(Example.UserWithTokenRequired, :log_out_everywhere)

      jtis =
        [0..3]
        |> Enum.map(fn _ ->
          {:ok, _token, %{"jti" => jti}} = Jwt.token_for_user(user)
          jti
        end)

      assert :ok = Strategy.action(strategy, :log_out_everywhere, %{user_id: user.id})

      for jti <- jtis do
        assert TokenResource.jti_revoked?(Example.UserWithTokenRequired, jti)
      end
    end
  end
end
