defmodule AshAuthentication.PasswordAuthentication.HTML do
  @moduledoc """
  Renders a very basic forms for using password authentication.

  These are mainly used for testing.
  """

  require EEx
  alias AshAuthentication.PasswordAuthentication

  EEx.function_from_string(
    :defp,
    :render_sign_in,
    ~s"""
      <form method="<%= @method %>" action="<%= @action %>">
        <input type="hidden" name="<%= @subject_name %>[action]" value="sign_in" />
        <fieldset>
          <%= if @legend do %><legend><%= @legend %></legend><% end %>
          <input type="text" name="<%= @subject_name %>[<%= @identity_field %>]" placeholder="<%= @identity_field %>" />
          <br />
          <input type="password" name="<%= @subject_name %>[<%= @password_field %>]" placeholder="Password" />
          <br />
          <input type="submit" value="Sign in" />
        </fieldset>
      </form>
    """,
    [:assigns]
  )

  EEx.function_from_string(
    :defp,
    :render_register,
    ~s"""
      <form method="<%= @method %>" action="<%= @action %>">
        <input type="hidden" name="<%= @subject_name %>[action]" value="<%= @register_action_name %>" />
        <fieldset>
          <%= if @legend do %><legend><%= @legend %></legend><% end %>
          <input type="text" name="<%= @subject_name %>[<%= @identity_field %>]" placeholder="register" />
          <br />
          <input type="password" name="<%= @subject_name %>[<%= @password_field %>]" placeholder="Password" />
          <br />
          <%= if @confirmation_required? do %>
            <input type="password" name="<%= @subject_name %>[<%= @password_confirmation_field %>]" placeholder="Password confirmation" />
          <br />
          <% end %>
          <input type="submit" value="Register" />
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
  Render a basic HTML sign-in form.
  """
  @spec sign_in(module, options) :: String.t()
  def sign_in(resource, options) do
    resource
    |> build_assigns(options)
    |> render_sign_in()
  end

  @doc """
  Render a basic HTML registration form.
  """
  @spec register(module, options) :: String.t()
  def register(resource, options) do
    resource
    |> build_assigns(options)
    |> render_register()
  end

  defp build_assigns(resource, options) do
    @defaults
    |> Keyword.merge(options)
    |> Map.new()
    |> Map.merge(PasswordAuthentication.Info.options(resource))
    |> Map.merge(AshAuthentication.Info.authentication_options(resource))
  end
end
