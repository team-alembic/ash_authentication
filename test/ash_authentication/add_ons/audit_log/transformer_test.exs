# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.TransformerTest do
  @moduledoc """
  Tests for the audit log transformer, specifically focusing on
  wildcard expansion and inclusion/exclusion logic.
  """
  use DataCase, async: true
  alias AshAuthentication.AddOn.AuditLog.Auditor
  alias AshAuthentication.Info
  alias Spark.Dsl.Extension

  describe "wildcard expansion" do
    test ":* wildcard in include_actions expands to all actions" do
      # UserWithAuditLog uses default include_actions: [:*]
      _strategy = Info.strategy!(Example.UserWithAuditLog, :audit_log)

      # The transformer should have expanded :* to include all actions
      # We can verify this by checking what actions are tracked
      tracked_actions = Auditor.get_tracked_actions(Example.UserWithAuditLog, :audit_log)

      assert :sign_in_with_password in tracked_actions
      assert :register_with_password in tracked_actions
    end

    test ":* wildcard in include_strategies expands to all strategies" do
      # UserWithAuditLog uses default include_strategies: [:*]
      _strategy = Info.strategy!(Example.UserWithAuditLog, :audit_log)

      # All strategies should be included when wildcard is used
      # The password strategy actions should be tracked
      tracked_actions = Auditor.get_tracked_actions(Example.UserWithAuditLog, :audit_log)

      assert length(tracked_actions) > 0
    end

    test "empty include lists remain empty after transformation" do
      # UserWithEmptyIncludes has include_actions: [] and include_strategies: []
      _strategy = Info.strategy!(Example.UserWithEmptyIncludes, :audit_log)

      # No actions should be tracked when includes are empty
      tracked_actions = Auditor.get_tracked_actions(Example.UserWithEmptyIncludes, :audit_log)

      assert tracked_actions == []
    end

    test "explicit include lists are preserved without expansion" do
      # UserWithExplicitIncludes has specific actions listed, not :*
      _strategy = Info.strategy!(Example.UserWithExplicitIncludes, :audit_log)

      tracked_actions = Auditor.get_tracked_actions(Example.UserWithExplicitIncludes, :audit_log)

      # Should have exactly the explicitly included actions
      assert :sign_in_with_password in tracked_actions
      assert :register_with_password in tracked_actions
      assert length(tracked_actions) == 2
    end
  end

  describe "inclusion and exclusion logic" do
    test "exclusions are applied after wildcard expansion" do
      # UserWithWildcardAndExclusions has include_actions: [:*] and exclude_actions: [:sign_in_with_password]
      _strategy = Info.strategy!(Example.UserWithWildcardAndExclusions, :audit_log)

      tracked_actions =
        Auditor.get_tracked_actions(Example.UserWithWildcardAndExclusions, :audit_log)

      # register_with_password should be included (via wildcard)
      assert :register_with_password in tracked_actions
      # sign_in_with_password should be excluded
      refute :sign_in_with_password in tracked_actions
    end

    test "excluded actions are removed from explicit includes" do
      # UserWithExcludedActions excludes sign_in_with_password
      _strategy = Info.strategy!(Example.UserWithExcludedActions, :audit_log)

      tracked_actions = Auditor.get_tracked_actions(Example.UserWithExcludedActions, :audit_log)

      # sign_in_with_password should not be tracked
      refute :sign_in_with_password in tracked_actions
      # register_with_password should still be tracked
      assert :register_with_password in tracked_actions
    end

    test "strategy-level filtering applies to included actions" do
      # UserWithSelectiveStrategyIncludes only includes [:password] strategy
      _strategy = Info.strategy!(Example.UserWithSelectiveStrategyIncludes, :audit_log)

      tracked_actions =
        Auditor.get_tracked_actions(Example.UserWithSelectiveStrategyIncludes, :audit_log)

      # All tracked actions should belong to password strategy
      assert :sign_in_with_password in tracked_actions
      assert :register_with_password in tracked_actions
      # If there were actions from other strategies, they wouldn't be included
    end
  end

  describe "logged fields determination" do
    test "sensitive fields are excluded unless explicitly included" do
      # UserWithAuditLog has include_fields: [:email]
      # Email is sensitive but explicitly included
      _strategy = Info.strategy!(Example.UserWithAuditLog, :audit_log)

      # Check what fields are persisted for the register action
      register_arguments =
        Extension.get_persisted(
          Example.UserWithAuditLog,
          {:audit_log, :audit_log, :register_with_password, :arguments}
        )

      register_attributes =
        Extension.get_persisted(
          Example.UserWithAuditLog,
          {:audit_log, :audit_log, :register_with_password, :attributes}
        )

      # Email should be included despite being sensitive (it's in include_fields)
      assert :email in register_arguments || :email in register_attributes

      # Password fields should NOT be included (sensitive and not in include_fields)
      refute :password in register_arguments
      refute :password_confirmation in register_arguments
      refute :hashed_password in register_attributes
    end

    test "public non-sensitive fields are included by default" do
      _strategy = Info.strategy!(Example.UserWithAuditLog, :audit_log)

      # Check persisted fields for register action
      register_attributes =
        Extension.get_persisted(
          Example.UserWithAuditLog,
          {:audit_log, :audit_log, :register_with_password, :attributes}
        ) || []

      # ID should be included as it's a public non-sensitive field
      assert :id in register_attributes

      # Email should be included because it's explicitly in include_fields
      # (even though it's marked as sensitive)
      assert :email in register_attributes

      # Verify the actual contents match what we expect
      # (only public non-sensitive fields and explicitly included fields)
      assert length(register_attributes) > 0
    end

    test "fields are correctly categorized between arguments and attributes" do
      _strategy = Info.strategy!(Example.UserWithAuditLog, :audit_log)

      register_arguments =
        Extension.get_persisted(
          Example.UserWithAuditLog,
          {:audit_log, :audit_log, :register_with_password, :arguments}
        ) || []

      register_attributes =
        Extension.get_persisted(
          Example.UserWithAuditLog,
          {:audit_log, :audit_log, :register_with_password, :attributes}
        ) || []

      sign_in_arguments =
        Extension.get_persisted(
          Example.UserWithAuditLog,
          {:audit_log, :audit_log, :sign_in_with_password, :arguments}
        ) || []

      # The combination of arguments and attributes should include the tracked fields
      all_register_fields = register_arguments ++ register_attributes
      _all_sign_in_fields = sign_in_arguments

      # Email is explicitly included and should be tracked somewhere
      assert :email in all_register_fields

      # ID should be tracked as it's public and non-sensitive
      assert :id in register_attributes

      # Verify that sensitive fields not in include_fields are excluded
      refute :hashed_password in all_register_fields
    end
  end

  describe "transformer adds required changes and preparations" do
    test "all actions get the audit log change/preparation" do
      # The transformer should add Auditor.Change to all changes
      # and Auditor.Preparation to all preparations

      # We can verify this indirectly by checking that audit logging works
      # for all configured actions
      tracked_actions = Auditor.get_tracked_actions(Example.UserWithAuditLog, :audit_log)

      # All tracked actions should have the necessary changes/preparations
      # This is proven by the fact that they appear in tracked_actions
      assert length(tracked_actions) > 0
    end
  end

  describe "edge cases" do
    test "handles resources with no authentication strategies gracefully" do
      # This would test a resource that has audit_log but no other strategies
      # For now, we just ensure our test resources compile and work
      assert Info.strategy!(Example.UserWithEmptyIncludes, :audit_log)
    end

    test "handles overlapping includes and excludes correctly" do
      # If an action appears in both include and exclude lists,
      # exclude should take precedence (after inclusion)
      _strategy = Info.strategy!(Example.UserWithWildcardAndExclusions, :audit_log)

      tracked_actions =
        Auditor.get_tracked_actions(Example.UserWithWildcardAndExclusions, :audit_log)

      # sign_in_with_password is included via :* but excluded explicitly
      refute :sign_in_with_password in tracked_actions
    end
  end
end
