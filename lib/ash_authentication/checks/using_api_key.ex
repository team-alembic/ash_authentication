# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Checks.UsingApiKey do
  @moduledoc """
  This check is true if `user.__metadata__[:using_api_key?]` is set to true.
  """
  use Ash.Policy.SimpleCheck

  @impl Ash.Policy.Check
  def describe(_) do
    "signed in with an API key"
  end

  @impl Ash.Policy.SimpleCheck
  def match?(%{__metadata__: %{using_api_key?: true}}, _, _), do: true
  def match?(_, _, _), do: false
end
