defmodule AshAuthentication.AddOn.TwoFactorTotp.Dsl do
  @moduledoc """
  Defines the Spark DSL entity for this add on.
  """

  @doc false
  @spec dsl :: map()
  def dsl do
    %Spark.Dsl.Entity{
      name: :two_factor_totp,
      describe: "Add-on that requires users to provide a second factor TOTP for authentication",
      examples: [
        """
        two_factor_totp do
          issuer "My Company"
          storage_field :super_sekrit_totp
        end
        """
      ],
      target: AshAuthentication.AddOn.TwoFactorTotp,
      args: [{:optional, :name, :two_factor_totp}],
      schema: [
        name: [
          type: :atom,
          doc: "Uniquely identifies the add-on.",
          required: true
        ],
        storage_field: [
          type: :atom,
          doc: "The name of the field to store the user's TOTP authentication details in.",
          default: :totp_details
        ],
        verify_action_name: [
          type: :atom,
          doc:
            "The name to use for the TOTP verification action. Defaults to `verify_<strategy_name>`.",
          required: false
        ],
        issuer: [
          type: :string,
          doc: "The issuer name to use for the TOTP. Usually the company name.",
          required: true
        ]
        # Strategies to apply this add-on to?
        # Grace period - https://hexdocs.pm/nimble_totp/NimbleTOTP.html#module-grace-period
      ]
    }
  end
end
