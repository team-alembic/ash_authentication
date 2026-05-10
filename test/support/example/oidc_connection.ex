# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.OidcConnection do
  @moduledoc false
  use Ash.Resource,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication.OidcConnection],
    domain: Example

  oidc_connection do
    domain(Example)
  end

  actions do
    defaults([:read, :destroy, create: :*, update: :*])
  end

  ets do
    private?(true)
  end
end
