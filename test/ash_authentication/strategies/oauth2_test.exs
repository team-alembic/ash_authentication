# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2Test do
  @moduledoc false
  use DataCase, async: true
  alias AshAuthentication.Strategy.OAuth2
  doctest OAuth2

  describe "uid_from_user_info/1" do
    test "it prefers `sub` when all three keys are present" do
      assert "OIDC-SUB" ==
               OAuth2.uid_from_user_info(%{
                 "uid" => "AUTH-UID",
                 "sub" => "OIDC-SUB",
                 "id" => "LEGACY-ID"
               })
    end

    test "it prefers `sub` over `uid`" do
      assert "OIDC-SUB" ==
               OAuth2.uid_from_user_info(%{"uid" => "AUTH-UID", "sub" => "OIDC-SUB"})
    end

    test "it prefers `sub` over `id`" do
      assert "OIDC-SUB" ==
               OAuth2.uid_from_user_info(%{"sub" => "OIDC-SUB", "id" => "LEGACY-ID"})
    end

    test "it prefers `uid` over `id`" do
      assert "AUTH-UID" ==
               OAuth2.uid_from_user_info(%{"uid" => "AUTH-UID", "id" => "LEGACY-ID"})
    end

    test "it falls back to `id` when it is the only key present" do
      assert "LEGACY-ID" == OAuth2.uid_from_user_info(%{"id" => "LEGACY-ID"})
    end

    test "it skips a key whose value is nil" do
      assert "AUTH-UID" ==
               OAuth2.uid_from_user_info(%{
                 "sub" => nil,
                 "uid" => "AUTH-UID",
                 "id" => "LEGACY-ID"
               })
    end

    test "it prefers a string key over the equivalent atom key" do
      assert "STRING-SUB" ==
               OAuth2.uid_from_user_info(%{"sub" => "STRING-SUB", sub: "ATOM-SUB"})
    end

    test "it prefers a string key over a higher-precedence atom key" do
      assert "STRING-ID" == OAuth2.uid_from_user_info(%{"id" => "STRING-ID", sub: "ATOM-SUB"})
    end

    test "it uses atom keys in the same precedence when no string key is present" do
      assert "ATOM-SUB" == OAuth2.uid_from_user_info(%{sub: "ATOM-SUB", id: "ATOM-ID"})
    end

    test "it stringifies a non-binary value" do
      assert "1234" == OAuth2.uid_from_user_info(%{"sub" => 1234})
    end

    test "it returns nil when no key is present" do
      assert nil == OAuth2.uid_from_user_info(%{"nickname" => "marty"})
    end

    test "it returns nil when every key is nil" do
      assert nil == OAuth2.uid_from_user_info(%{"sub" => nil, "uid" => nil, "id" => nil})
    end
  end
end
