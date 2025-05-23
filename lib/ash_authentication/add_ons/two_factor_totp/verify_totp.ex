defmodule AshAuthentication.AddOn.TwoFactorTotp.VerifyTotp do
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    entered_totp = Ash.Changeset.get_argument(changeset, :totp)
    strategy = AshAuthentication.Info.strategy!(changeset.resource, :two_factor_totp)

    totp_details = Map.fetch!(changeset.data, strategy.storage_field)
    secret = Map.fetch!(totp_details, :secret)

    if NimbleTOTP.valid?(:binary.decode_hex(secret), entered_totp) do
      updated_details =
        Map.merge(totp_details, %{
          confirmed?: true,
          last_used_at: DateTime.utc_now()
        })

      Ash.Changeset.change_attribute(changeset, strategy.storage_field, updated_details)
    else
      Ash.Changeset.add_error(changeset, "Invalid TOTP provided")
    end
  end

  @impl true
  def atomic(changeset, opts, context) do
    {:ok, change(changeset, opts, context)}
  end
end
