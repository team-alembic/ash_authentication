defmodule AshAuthentication do
  @authentication %Spark.Dsl.Section{
    name: :authentication,
    describe: "Configure authentication for this resource",
    schema: [
      subject_name: [
        type: :atom,
        doc: """
        The subject name is used in generating token claims and in generating authentication routes.
        """
      ],
      api: [
        type: {:behaviour, Ash.Api},
        doc: """
        The name of the Ash API to use to access this resource when registering/authenticating.
        """
      ],
      get_by_subject_action_name: [
        type: :atom,
        doc: """
        The name of the read action used to retrieve the access when calling `AshAuthentication.subject_to_resource/2`.
        """,
        default: :get_by_subject
      ]
    ]
  }

  @moduledoc """
  AshAuthentication

  AshAuthentication provides a turn-key authentication solution for folks using
  [Ash](https://www.ash-hq.org/).


  ## DSL Documentation

  ### Index

  #{Spark.Dsl.Extension.doc_index([@authentication])}

  ### Docs

  #{Spark.Dsl.Extension.doc([@authentication])}
  """
  alias Ash.{Api, Query, Resource}
  alias AshAuthentication.Info
  alias Spark.Dsl.Extension

  use Spark.Dsl.Extension,
    sections: [@authentication],
    transformers: [AshAuthentication.Transformer]

  @type resource_config :: %{
          api: module,
          providers: [module],
          resource: module,
          subject_name: atom
        }

  @type subject :: String.t()

  @doc """
  Find all resources which support authentication for a given OTP application.

  Returns a map where the key is the authentication provider, and the values are
  lists of api/resource pairs.

  This is primarily useful for introspection, but also allows us to simplify
  token lookup.
  """
  @spec authenticated_resources(atom) :: [resource_config]
  def authenticated_resources(otp_app) do
    otp_app
    |> Application.get_env(:ash_apis, [])
    |> Stream.flat_map(&Api.Info.resources(&1))
    |> Stream.map(&{&1, Extension.get_persisted(&1, :authentication)})
    |> Stream.reject(&(elem(&1, 1) == nil))
    |> Stream.map(fn {resource, config} ->
      Map.put(config, :resource, resource)
    end)
    |> Enum.to_list()
  end

  @doc """
  Return a subject string for an AshAuthentication resource.
  """
  @spec resource_to_subject(Resource.record()) :: subject
  def resource_to_subject(record) do
    subject_name =
      record.__struct__
      |> AshAuthentication.Info.subject_name!()

    record.__struct__
    |> Resource.Info.primary_key()
    |> then(&Map.take(record, &1))
    |> then(fn primary_key ->
      "#{subject_name}?#{URI.encode_query(primary_key)}"
    end)
  end

  @doc """
  Given a subject string, attempt to retrieve a resource.
  """
  @spec subject_to_resource(subject, %{api: module, resource: module, subject_name: atom}) ::
          {:ok, Resource.record()} | {:error, any}
  def subject_to_resource(subject, config) when is_map(config) do
    %{path: subject_name, query: primary_key} = URI.parse(subject)

    with ^subject_name <- to_string(config.subject_name),
         primary_key <- URI.decode_query(primary_key),
         {:ok, action_name} <- Info.get_by_subject_action_name(config.resource) do
      config.resource
      |> Query.for_read(action_name, primary_key)
      |> config.api.read()
      |> case do
        {:ok, [actor]} -> {:ok, actor}
        _ -> {:error, "Invalid subject"}
      end
    end
  end
end
