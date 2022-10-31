defmodule DevServer.JsonApiRouter do
  @moduledoc false
  use AshJsonApi.Api.Router, api: Example, registry: Example.Registry
end
