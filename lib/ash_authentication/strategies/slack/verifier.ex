# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Slack.Verifier do
  @moduledoc """
  DSL verifier for Slack strategy.
  """

  alias AshAuthentication.Strategy.{OAuth2, Oidc}
  import AshAuthentication.Validations

  @doc false
  @spec verify(OAuth2.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with :ok <- Oidc.Verifier.verify(strategy, dsl_state) do
      validate_secret(strategy, :team_id, [nil])
    end
  end
end
