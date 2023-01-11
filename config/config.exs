import Config

config :mime, :types, %{
  "application/vnd.api+json" => ["json"]
}

config :ash, :utc_datetime_type, :datetime
# resolve temporary backwards compatibility warning in Ash
config :ash, :use_all_identities_in_manage_relationship?, false

import_config "#{config_env()}.exs"
