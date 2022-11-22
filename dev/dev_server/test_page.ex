defmodule DevServer.TestPage do
  @moduledoc """
  Displays a very basic login form according to the currently configured
  Überauth providers.
  """
  @behaviour Plug
  alias AshAuthentication.{Info, Strategy}
  alias Plug.Conn
  require EEx

  EEx.function_from_file(:defp, :render, String.replace(__ENV__.file, ".ex", ".html.eex"), [
    :assigns
  ])

  @doc false
  @impl true
  @spec init(keyword) :: keyword
  def init(opts), do: opts

  @doc false
  @spec call(Conn.t(), any) :: Conn.t()
  @impl true
  def call(conn, _opts) do
    resources =
      :ash_authentication
      |> AshAuthentication.authenticated_resources()
      |> Enum.map(&{&1, Info.authentication_options(&1), Info.authentication_strategies(&1)})

    current_users =
      conn.assigns
      |> Stream.filter(fn {key, _value} ->
        key
        |> to_string()
        |> String.starts_with?("current_")
      end)
      |> Map.new()

    payload = render(resources: resources, current_users: current_users)
    Conn.send_resp(conn, 200, payload)
  end

  defp render_strategy(strategy, phase, options)
       when strategy.provider == :password and phase == :register do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend>Register with <%= @strategy.name %></legend>
          <input type="text" name="<%= @options.subject_name %>[<%= @strategy.identity_field %>]" placeholder="<%= @strategy.identity_field %>" />
          <br />
          <input type="password" name="<%= @options.subject_name %>[<%= @strategy.password_field %>]" placeholder="<%= @strategy.password_field %>" />
          <br />
          <%= if @strategy.confirmation_required? do %>
            <input type="password" name="<%= @options.subject_name %>[<%= @strategy.password_confirmation_field %>]" placeholder="<%= @strategy.password_confirmation_field %>" />
            <br />
          <% end %>
          <input type="submit" value="Register" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, options)
       when strategy.provider == :password and phase == :sign_in do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend>Sign in with <%= @strategy.name %></legend>
          <input type="text" name="<%= @options.subject_name %>[<%= @strategy.identity_field %>]" placeholder="<%= @strategy.identity_field %>" />
          <br />
          <input type="password" name="<%= @options.subject_name %>[<%= @strategy.password_field %>]" placeholder="<%= @strategy.password_field %>" />
          <br />
          <input type="submit" value="Sign in" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, options)
       when strategy.provider == :password and phase == :reset_request do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend><%= @strategy.name %> reset request</legend>
          <input type="text" name="<%= @options.subject_name %>[<%= @strategy.identity_field %>]" placeholder="<%= @strategy.identity_field %>" />
          <br />
          <input type="submit" value="Request reset" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, options)
       when strategy.provider == :password and phase == :reset do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend><%= @strategy.name %> reset request</legend>
          <input type="text" name="reset_token" placeholder="reset_token" />
          <br />
          <input type="password" name="<%= @options.subject_name %>[<%= @strategy.password_field %>]" placeholder="<%= @strategy.password_field %>" />
          <br />
          <%= if @strategy.confirmation_required? do %>
            <input type="password" name="<%= @options.subject_name %>[<%= @strategy.password_confirmation_field %>]" placeholder="<%= @strategy.password_confirmation_field %>" />
            <br />
          <% end %>
          <input type="submit" value="Reset" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, options)
       when strategy.provider == :confirmation and phase == :confirm do
    EEx.eval_string(
      ~s"""
      <form method="<%= @method %>" action="<%= @route %>">
        <fieldset>
          <legend><%= @strategy.name %></legend>
          <input type="text" name="confirm" placeholder="confirmation token" />
          <br />
          <input type="submit" value="Confirm" />
        </fieldset>
      </form>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase),
        options: options,
        method: Strategy.method_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, phase, _options)
       when strategy.provider == :oauth2 and phase == :request do
    EEx.eval_string(
      ~s"""
      <a href="<%= @route %>">Sign in with <%= @strategy.name %></a>
      """,
      assigns: [
        strategy: strategy,
        route: route_for_phase(strategy, phase)
      ]
    )
  end

  defp render_strategy(strategy, :callback, _) when strategy.provider == :oauth2, do: ""

  defp render_strategy(strategy, phase, _options) do
    inspect({strategy.provider, phase})
  end

  defp route_for_phase(strategy, phase) do
    path =
      strategy
      |> Strategy.routes()
      |> Enum.find(&(elem(&1, 1) == phase))
      |> elem(0)

    Path.join("/auth", path)
  end
end
