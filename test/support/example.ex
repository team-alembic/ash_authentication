# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example do
  @moduledoc false
  use Ash.Domain, otp_app: :ash_authentication, extensions: [AshGraphql.Domain, AshJsonApi.Domain]

  resources do
    resource Example.ApiKey
    resource Example.AuditLog
    resource Example.Token
    resource Example.TokenWithCustomCreateTimestamp
    resource Example.User
    resource Example.UserIdentity
    resource Example.UserWithAuditLog
    resource Example.UserWithEmptyIncludes
    resource Example.UserWithExcludedActions
    resource Example.UserWithExcludedStrategies
    resource Example.UserWithExplicitIncludes
    resource Example.UserWithRegisterMagicLink
    resource Example.UserWithRememberMe
    resource Example.UserWithSelectiveStrategyIncludes
    resource Example.UserWithTokenRequired
    resource Example.UserWithWildcardAndExclusions
    resource Example.UserWithExtraClaims
  end

  json_api do
    prefix "/api"
  end
end
