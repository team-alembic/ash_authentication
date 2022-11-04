defmodule AshAuthentication.Confirmation.Html do
  @moduledoc """
  Renders a very basic form for handling a confirmation token.

  These are mainly used for testing, and you should instead write your own or
  use the widgets in `ash_authentication_phoenix`.
  """

  require EEx
  alias AshAuthentication.Confirmation

  EEx.function_from_string(
    :defp,
    :render,
    ~s"""
      <form method="<%= @method %>" action="<%= @action %>">
        <fieldset>
          <%= if @legend do %><legend><%= @legend %></legend><% end %>
          <input type="text" name="confirm" placeholder="Confirmation token" />
          <br />
          <input type="submit" value="Confirm" />
        </fieldset>
      </form>
    """,
    [:assigns]
  )

  @defaults [method: "POST", legend: "Confirm"]

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

  @doc false
  @spec callback(module, options) :: String.t()
  def callback(_module, _options), do: ""

  @doc """
  Render a basic HTML confirmation form.
  """
  @spec request(module, options) :: String.t()
  def request(resource, options) do
    resource
    |> build_assigns(options)
    |> render()
  end

  defp build_assigns(resource, options) do
    @defaults
    |> Keyword.merge(options)
    |> Map.new()
    |> Map.merge(Confirmation.Info.options(resource))
    |> Map.merge(AshAuthentication.Info.authentication_options(resource))
  end
end
