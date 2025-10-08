# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.TokenWithCustomCreateTimestamp do
  @moduledoc false
  use Ash.Resource,
    extensions: [AshAuthentication.TokenResource],
    domain: Example

  token do
    created_at_attribute_name :inserted_at
  end
end
