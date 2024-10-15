defmodule AshAuthentication.UserWithBadTokenTest do
  @moduledoc false

  use DataCase, async: true

  test "cannot compile with bad token_resource configured" do
    assert_raise Spark.Error.DslError,
                 ~r/`BadToken` is not a valid token resource module name/,
                 fn ->
                   defmodule UserWithBadToken do
                     @moduledoc false
                     use Ash.Resource,
                       data_layer: AshPostgres.DataLayer,
                       extensions: [AshAuthentication],
                       validate_domain_inclusion?: false,
                       domain: Example

                     attributes do
                       uuid_primary_key :id, writable?: true
                       attribute :email, :ci_string, allow_nil?: false, public?: true

                       attribute :hashed_password, :string,
                         allow_nil?: true,
                         sensitive?: true,
                         public?: false

                       create_timestamp :created_at
                       update_timestamp :updated_at
                     end

                     authentication do
                       tokens do
                         enabled? true
                         token_resource BadToken
                         signing_secret fn _, _ -> :dummy end
                       end

                       strategies do
                         password do
                           identity_field :email

                           resettable do
                             sender fn _user, _token, _opts -> :noop end
                           end
                         end
                       end
                     end

                     actions do
                       defaults [:create, :read, :update, :destroy]
                     end

                     identities do
                       identity :email, [:email]
                     end

                     postgres do
                       table "user_with_bad_token_required"
                       repo(Example.Repo)
                     end
                   end
                 end
  end
end
