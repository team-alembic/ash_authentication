# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthenticationTest do
  @moduledoc false
  use DataCase, async: true
  import AshAuthentication
  doctest AshAuthentication

  describe "authenticated_resources/0" do
    test "it correctly locates all authenticatable resources" do
      assert [
               Example.User,
               Example.UserWithTokenRequired,
               Example.UserWithRememberMe,
               Example.UserWithRegisterMagicLink,
               ExampleMultiTenant.User,
               ExampleMultiTenant.GlobalUser,
               ExampleMultiTenant.UserWithTokenRequired,
               ExampleMultiTenant.UserWithRegisterMagicLink
             ] =
               authenticated_resources(:ash_authentication)
    end
  end
end
