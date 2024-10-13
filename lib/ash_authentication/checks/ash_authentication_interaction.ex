defmodule AshAuthentication.Checks.AshAuthenticationInteraction do
  @moduledoc """
  This check is true if the context `private.ash_authentication?` is set to true.

  This context will only ever be set in code that is called internally by
  `ash_authentication`, allowing you to create a bypass in your policies on your
  user/user_token resources.

  ```elixir
  policies do
    bypass AshAuthenticationInteraction do
      authorize_if always()
    end
  end
  ```
  """
  use Ash.Policy.SimpleCheck

  @impl Ash.Policy.Check
  def describe(_) do
    "AshAuthentication is performing this interaction"
  end

  @impl Ash.Policy.SimpleCheck
  def match?(_, %{subject: %{context: %{private: %{ash_authentication?: true}}}}, _), do: true
  def match?(_, _, _), do: false
end
