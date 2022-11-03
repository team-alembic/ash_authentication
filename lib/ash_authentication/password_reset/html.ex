defmodule AshAuthentication.PasswordReset.Html do
  @moduledoc """
  Renders a very basic form for password resetting.

  These are mainly used for testing, and you should instead write your own or
  use the widgets in `ash_authentication_phoenix`.
  """

  require EEx
  alias AshAuthentication.{PasswordAuthentication, PasswordReset}

  EEx.function_from_string(
    :defp,
    :render_request,
    ~s"""
    <form method="<%= @method %>" action="<%= @action %>">
      <fieldset>
        <%= if @legend do %><legend><%= @legend %></legend><% end %>
        <input type="text" name="<%= @subject_name %>[<%= @identity_field %>]" placeholder="<%= @identity_field %>" />
        <br />
        <input type="submit" value="Request password reset" />
      </fieldset>
    </form>
    """,
    [:assigns]
  )

  EEx.function_from_string(
    :defp,
    :render_reset,
    ~s"""
    <form method="<%= @method %>" action="<%= @action %>">
      <fieldset>
        <%= if @legend do %><legend><%= @legend %></legend><% end %>
        <input type="token" name="<%= @subject_name %>[reset_token]" placeholder="Reset token" />
        <br />
        <input type="password" name="<%= @subject_name %>[<%= @password_field %>]" placeholder="Password" />
        <br />
        <%= if @confirmation_required? do %>
          <input type="password" name="<%= @subject_name %>[<%= @password_confirmation_field %>]" placeholder="Password confirmation" />
          <br />
        <% end %>
        <input type="submit" value="Reset password" />
      </fieldset>
    </form>
    """,
    [:assigns]
  )

  @defaults [method: "POST", legend: nil]

  @type options :: [method_option | action_option]

  @typedoc """
  The HTTP method used to submit the form.

  Defaults to `#{inspect(Keyword.get(@defaults, :method))}`.
  """
  @type method_option :: {:method, String.t()}

  @typedoc """
  The path/URL to which the form should be submitted.
  """
  @type action_option :: {:action, String.t()}

  @doc """
  Render a reset request.
  """
  @spec request(module, options) :: String.t()
  def request(resource, options) do
    resource
    |> build_assigns(Keyword.put(options, :legend, "Request password reset"))
    |> render_request()
  end

  @doc """
  Render a reset form
  """
  @spec callback(module, options) :: String.t()
  def callback(resource, options) do
    resource
    |> build_assigns(Keyword.put(options, :legend, "Reset password"))
    |> render_reset()
  end

  defp build_assigns(resource, options) do
    @defaults
    |> Keyword.merge(options)
    |> Map.new()
    |> Map.merge(PasswordAuthentication.Info.password_authentication_options(resource))
    |> Map.merge(PasswordReset.Info.options(resource))
    |> Map.merge(AshAuthentication.Info.authentication_options(resource))
  end
end
