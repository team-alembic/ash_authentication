defmodule Example.Repo.Migrations.AddRecoveryCodeResources do
  @moduledoc """
  Add recovery code test resources.
  """

  use Ecto.Migration

  def up do
    create table(:recovery_code_users, primary_key: false) do
      add(:id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true)
      add(:email, :citext, null: false)
      add(:hashed_password, :text)

      add(:inserted_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")
      )

      add(:updated_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")
      )
    end

    create unique_index(:recovery_code_users, [:email],
             name: "recovery_code_users_unique_email_index"
           )

    create table(:recovery_codes, primary_key: false) do
      add(:id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true)
      add(:code, :text, null: false)

      add(:user_id, references(:recovery_code_users, type: :uuid, on_delete: :delete_all),
        null: false
      )

      add(:inserted_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")
      )

      add(:updated_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")
      )
    end

    create index(:recovery_codes, [:user_id])
  end

  def down do
    drop_if_exists(index(:recovery_codes, [:user_id]))
    drop_if_exists(table(:recovery_codes))

    drop_if_exists(
      unique_index(:recovery_code_users, [:email],
        name: "recovery_code_users_unique_email_index"
      )
    )

    drop_if_exists(table(:recovery_code_users))
  end
end
