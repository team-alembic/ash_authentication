# SPDX-FileCopyrightText: 2026 ash_authentication contributors <https://github.com/team-alembic/ash_authentication/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Example.Vault do
  @moduledoc false
  use Cloak.Vault, otp_app: :ash_authentication
end
