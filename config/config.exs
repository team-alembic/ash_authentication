# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

import Config

config :mime, :types, %{
  "application/vnd.api+json" => ["json-api"]
}

config :ash, :utc_datetime_type, :datetime

config :ash_authentication, bypass_require_interaction_for_magic_link?: true

import_config "#{config_env()}.exs"
