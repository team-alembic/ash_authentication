defmodule AshAuthentication.Plug.Router do
  @moduledoc """
  Dynamically generates the authentication router for the authentication
  requests and callbacks.

  Used internally by `AshAuthentication.Plug`.
  """

  @doc false
  @spec __using__(keyword) :: Macro.t()
  defmacro __using__(opts) do
    otp_app =
      opts
      |> Keyword.fetch!(:otp_app)
      |> Macro.expand_once(__CALLER__)

    return_to =
      opts
      |> Keyword.fetch!(:return_to)
      |> Macro.expand_once(__CALLER__)

    routes =
      otp_app
      |> AshAuthentication.authenticated_resources()
      |> Stream.flat_map(fn config ->
        subject_name =
          config.subject_name
          |> to_string()

        config
        |> Map.get(:providers, [])
        |> Stream.map(fn provider ->
          config =
            config
            |> Map.delete(:providers)
            |> Map.put(:provider, provider)

          {{subject_name, provider.provides()}, config}
        end)
      end)
      |> Map.new()
      |> Macro.escape()

    quote generated: true do
      use Plug.Router
      plug(:match)
      plug(:dispatch)

      match("/:subject_name/:provider",
        to: AshAuthentication.Plug.Dispatcher,
        init_opts: [{:request, unquote(routes), unquote(return_to)}]
      )

      match("/:subject_name/:provider/callback",
        to: AshAuthentication.Plug.Dispatcher,
        init_opts: [{:callback, unquote(routes), unquote(return_to)}]
      )

      match(_,
        to: AshAuthentication.Plug.Dispatcher,
        init_opts: [{:noop, [], unquote(return_to)}]
      )
    end
  end
end
