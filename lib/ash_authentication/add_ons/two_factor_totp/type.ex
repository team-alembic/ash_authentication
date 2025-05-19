defmodule AshAuthentication.AddOn.TwoFactorTotp.Types.StorageDetails do
  use Ash.Resource, data_layer: :embedded

  attributes do
    attribute :secret, :string, allow_nil?: false, public?: true
    attribute :confirmed?, :boolean, default: false, allow_nil?: false, public?: true
    attribute :last_used_at, :utc_datetime_usec, default: nil, public?: true
  end
end
