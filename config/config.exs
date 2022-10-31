import Config

config :mime, :types, %{
  "application/vnd.api+json" => ["json"]
}

import_config "#{config_env()}.exs"
