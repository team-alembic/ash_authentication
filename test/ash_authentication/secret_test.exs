defmodule AshAuthentication.SecretTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Errors, Secret}

  defmodule TestSecretModule do
    @moduledoc false
    use AshAuthentication.Secret

    def secret_for([:test, :valid_secret], _resource, _opts, _context) do
      {:ok, "valid_secret_value"}
    end

    def secret_for([:test, :invalid_direct_return], _resource, _opts, _context) do
      "direct_string_without_ok_tuple"
    end

    def secret_for([:test, :missing_secret], _resource, _opts, _context) do
      :error
    end
  end

  describe "secret_for/5" do
    test "returns {:ok, value} for successful secret retrieval" do
      result =
        Secret.secret_for(
          TestSecretModule,
          [:test, :valid_secret],
          Example.User,
          [],
          %{}
        )

      assert {:ok, "valid_secret_value"} = result
    end

    test "returns :error for missing secrets" do
      result =
        Secret.secret_for(
          TestSecretModule,
          [:test, :missing_secret],
          Example.User,
          [],
          %{}
        )

      assert :error = result
    end

    test "raises InvalidSecret error for invalid return values" do
      assert_raise Errors.InvalidSecret,
                   ~r/Secret for `test.invalid_direct_return` on the `Example.User` resource returned an invalid value\. Expected an `:ok` tuple, or `:error`\./,
                   fn ->
                     Secret.secret_for(
                       TestSecretModule,
                       [:test, :invalid_direct_return],
                       Example.User,
                       [],
                       %{}
                     )
                   end
    end
  end
end
