# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.OAuthTokensTest do
  @moduledoc """
  The audit log persists any action field which is public and not sensitive.

  An OAuth2 register action carries the provider's token response in its
  `oauth_tokens` argument, so the argument must be sensitive or the audit table
  keeps a plaintext copy of every access and refresh token.
  """
  use DataCase, async: false

  alias AshAuthentication.{AddOn.AuditLog.Auditor, AuditLogResource.Batcher}
  alias Spark.Dsl.Extension

  @access_token "audit-access-token-value"
  @refresh_token "audit-refresh-token-value"

  setup do
    start_supervised!({Batcher, otp_app: :ash_authentication})
    :ok
  end

  test "the `oauth_tokens` argument is not in the persisted field list" do
    arguments =
      Extension.get_persisted(
        Example.UserWithOAuthAuditLog,
        {:audit_log, :audit_log, :register_with_oauth2, :arguments}
      )

    assert :register_with_oauth2 in Auditor.get_tracked_actions(
             Example.UserWithOAuthAuditLog,
             :audit_log
           )

    assert :user_info in arguments
    refute :oauth_tokens in arguments
  end

  test "an OAuth2 registration does not write the provider tokens to the audit log" do
    uid = System.unique_integer([:positive])

    params = %{
      "user_info" => %{"sub" => "uid-#{uid}", "email" => "audit-#{uid}@example.com"},
      "oauth_tokens" => %{
        "access_token" => @access_token,
        "refresh_token" => @refresh_token
      }
    }

    strategy = AshAuthentication.Info.strategy!(Example.UserWithOAuthAuditLog, :oauth2)
    {:ok, _user} = AshAuthentication.Strategy.action(strategy, :register, params, [])

    Batcher.flush()

    assert [log] =
             Example.AuditLog
             |> Ash.read!()
             |> Enum.filter(&(&1.action_name == :register_with_oauth2))

    refute inspect(log.extra_data) =~ @access_token
    refute inspect(log.extra_data) =~ @refresh_token
    refute Map.has_key?(log.extra_data["params"], "oauth_tokens")
  end
end
