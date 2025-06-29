defmodule AshAuthentication.Strategy.RememberMe.CookieTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.RememberMe.Cookie

  describe "cookie_name/1" do
    test "returns prefix for :remember_me" do
      assert Cookie.cookie_name(:remember_me) == "ash_auth:remember_me"
    end

    test "returns prefix for 'remember_me'" do
      assert Cookie.cookie_name("remember_me") == "ash_auth:remember_me"
    end

    test "returns prefixed name for custom cookie name" do
      assert Cookie.cookie_name(:custom_cookie) == "ash_auth:remember_me:custom_cookie"
      assert Cookie.cookie_name("custom_cookie") == "ash_auth:remember_me:custom_cookie"
    end
  end

  describe "prefix/0" do
    test "returns the cookie name prefix" do
      assert Cookie.prefix() == "ash_auth:remember_me"
    end
  end
end
