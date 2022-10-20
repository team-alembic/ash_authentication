defmodule AshAuthentication.TokenRevocation do
  @revocation %Spark.Dsl.Section{
    name: :revocation,
    describe: "Configure revocation options for this resource",
    schema: [
      api: [
        type: {:behaviour, Ash.Api},
        doc: """
        The Ash API to use to access this resource.
        """,
        required: true
      ]
    ]
  }

  @moduledoc """
  An Ash extension which generates the defaults for a token revocation resource.

  The token revocation resource is used to store the Json Web Token ID an expiry
  times of any tokens which have been revoked.  These will be removed once the
  expiry date has passed, so should only ever be a fairly small number of rows.

  ## Storage

  Token revocations are ephemeral, but their lifetime directly correlates to the
  lifetime of your tokens - ie if you have a long expiry time on your tokens you
  have to keep the revation records for longer.  Therefore we suggest a (semi)
  permanent data layer, such as Postgres.

  ## Usage

  There is no need to define any attributes, etc.  The extension will generate
  them all for you.  As there is no other use-case for this resource, it's
  unlikely that you will need to customise it.

  ```elixir
  defmodule MyApp.Accounts.TokenRevocation do
    use Ash.Resource,
      data_layer: AshPostgres.DataLayer,
      extensions: [AshAuthentication.TokenRevocation]

    revocation do
      api(MyApp.Api)
    end

    postgres do
      table("token_revocations")
      repo(MyApp.Repo)
    end
  end
  ```

  Whilst it's possible to have multiple token revocation resources, in practice
  there is no need to.

  ## Dsl

  ### Index

  #{Spark.Dsl.Extension.doc_index([@revocation])}

  ### Docs

  #{Spark.Dsl.Extension.doc([@revocation])}
  """

  use Spark.Dsl.Extension,
    sections: [@revocation],
    transformers: [AshAuthentication.TokenRevocation.Transformer]

  alias AshAuthentication.TokenRevocation.Info
  alias Ash.{Changeset, DataLayer, Query, Resource}

  @doc """
  Revoke a token.
  """
  @spec revoke(Resource.t(), token :: String.t()) ::
          {:ok, Resource.record()} | {:error, any}
  def revoke(resource, token) do
    with {:ok, api} <- Info.api(resource) do
      resource
      |> Changeset.for_create(:revoke_token, %{token: token})
      |> api.create(upsert?: true)
    end
  end

  @doc """
  Find out if (via it's JTI) a token has been revoked?
  """
  @spec revoked?(Resource.t(), jti :: String.t()) :: boolean
  def revoked?(resource, jti) do
    with {:ok, api} <- Info.api(resource) do
      resource
      |> Query.for_read(:revoked, %{jti: jti})
      |> api.read()
      |> case do
        {:ok, []} -> false
        _ -> true
      end
    end
  end

  @doc """
  The opposite of `revoked?/2`
  """
  @spec valid?(Resource.t(), jti :: String.t()) :: boolean
  def valid?(resource, jti), do: not revoked?(resource, jti)

  @doc """
  Expunge expired revocations.

  ## Note

  Sadly this function iterates over all expired revocations and delete them
  individually because Ash (as of v2.1.0) does not yet support bulk actions and
  we can't just drop down to Ecto because we can't assume that the user's
  resource uses an Ecto-backed data layer.

  Luckily, this function is only run periodically, so it shouldn't be a huge
  cost.  Contact the maintainers if it becomes a problem for you.
  """
  @spec expunge(Resource.t()) :: :ok | {:error, any}
  def expunge(resource) do
    DataLayer.transaction(
      resource,
      fn ->
        with {:ok, api} <- Info.api(resource),
             query <- Query.for_read(resource, :expired),
             {:ok, expired} <- api.read(query) do
          expired
          |> Stream.map(&remove_revocation/1)
          |> Enum.reduce_while(:ok, fn
            :ok, _ -> {:cont, :ok}
            {:error, reason}, _ -> {:halt, {:error, reason}}
          end)
        end
      end,
      5000
    )
  end

  @doc """
  Removes a revocation.

  ## Warning

  If the revocation in question is not yet expired, then this has the effect of
  making this token valid again.

  You are unlikely to need to do this, as `AshAuthentication` will periodically
  remove all expired revocations automatically, however it is provided here in
  case you need it.
  """
  @spec remove_revocation(Resource.record()) :: :ok | {:error, any}
  def remove_revocation(revocation) do
    with {:ok, api} <- Info.api(revocation.__struct__) do
      revocation
      |> Changeset.for_destroy(:expire)
      |> api.destroy()
      |> case do
        :ok -> :ok
        {:ok, _} -> :ok
        {:ok, _, _} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end
  end
end
