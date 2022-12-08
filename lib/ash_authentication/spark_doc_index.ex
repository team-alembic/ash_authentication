defmodule AshAuthentication.SparkDocIndex do
  @moduledoc false

  use Spark.DocIndex, otp_app: :ash_authentication, guides_from: ["documentation/**/*.md"]

  @doc false
  @impl true
  @spec for_library :: String.t()
  def for_library, do: "ash_authentication"

  @doc false
  @impl true
  @spec extensions :: [Spark.DocIndex.extension()]
  def extensions do
    [
      %{
        module: AshAuthentication,
        name: "Authentication",
        target: "Ash.Resource",
        type: "Authentication"
      },
      %{
        module: AshAuthentication.TokenResource,
        name: "Token Resource",
        target: "Ash.Resource",
        type: "Token"
      },
      %{
        module: AshAuthentication.UserIdentity,
        name: "User Identity",
        target: "Ash.Resource",
        type: "User identity"
      }
    ]
  end

  @doc false
  @impl true
  @spec mix_tasks :: [{String.t(), [module]}]
  def mix_tasks, do: []

  @doc false
  @impl true
  @spec code_modules :: [{String.t(), [module]}]
  def code_modules do
    [
      {"Authentication",
       [
         AshAuthentication,
         AshAuthentication.Info,
         AshAuthentication.TokenResource,
         AshAuthentication.Supervisor
       ]},
      {"Strategies",
       [
         AshAuthentication.Strategy,
         AshAuthentication.Strategy.Password,
         AshAuthentication.Strategy.OAuth2
       ]},
      {"Add Ons",
       [
         AshAuthentication.AddOn.Confirmation
       ]}
    ]
  end
end
