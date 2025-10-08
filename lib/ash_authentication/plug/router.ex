# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Plug.Router do
  @moduledoc """
  Dynamically generates the authentication router for the authentication
  requests and callbacks.

  Used internally by `AshAuthentication.Plug`.
  """

  alias AshAuthentication.{Info, Plug.Dispatcher, Strategy}

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

    quote do
      use Plug.Router
      plug(:match)
      plug(:dispatch)

      routes =
        unquote(otp_app)
        |> Application.compile_env(:ash_domains, [])
        |> Stream.flat_map(&Ash.Domain.Info.resources(&1))
        |> Stream.filter(&(AshAuthentication in Spark.extensions(&1)))
        |> Stream.flat_map(
          &(Info.authentication_strategies(&1) ++ Info.authentication_add_ons(&1))
        )
        |> Stream.flat_map(fn strategy ->
          strategy
          |> Strategy.routes()
          |> Stream.map(fn {path, phase} ->
            {path, Strategy.method_for_phase(strategy, phase),
             {phase, strategy, unquote(return_to)}}
          end)
        end)

      for {path, method, config} <- routes do
        match(path, to: Dispatcher, via: [method], init_opts: [config])
      end

      match(_, to: Dispatcher, init_opts: [unquote(return_to)])
    end
  end
end
