# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnCredential.Info do
  @moduledoc """
  Introspection functions for the `AshAuthentication.WebAuthnCredential` extension.
  """

  use Spark.InfoGenerator,
    extension: AshAuthentication.WebAuthnCredential,
    sections: [:webauthn_credential]
end
