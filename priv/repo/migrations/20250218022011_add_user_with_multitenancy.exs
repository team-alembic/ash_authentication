defmodule Example.Repo.Migrations.AddUserWithMultitenancy do
  @moduledoc """
  Updates resources based on their most recent snapshots.

  This file was autogenerated with `mix ash_postgres.generate_migrations`
  """

  use Ecto.Migration

  def up do
    create table(:user_with_multitenancy, primary_key: false) do
      add(:id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true)
      add(:email, :citext, null: false)
      add(:hashed_password, :text)
      add(:tenant, :text, null: false)

      add(:created_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")
      )

      add(:updated_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")
      )
    end

    create unique_index(:user_with_multitenancy, [:tenant, :email],
             name: "user_with_multitenancy_email_index"
           )
  end

  def down do
    drop_if_exists(
      unique_index(:user_with_multitenancy, [:tenant, :email],
        name: "user_with_multitenancy_email_index"
      )
    )

    drop(table(:user_with_multitenancy))
  end
end
