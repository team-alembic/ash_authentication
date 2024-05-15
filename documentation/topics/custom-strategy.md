# Defining Custom Authentication Strategies

AshAuthentication allows you to bring your own authentication strategy without
having to change the Ash Authentication codebase.

> #### Add-on vs Strategy? {:.info}
>
> There is functionally no difference between "add ons" and "strategies" other
> than where they appear in the DSL. We invented "add ons" because it felt
> weird calling "confirmation" an authentication strategy.

There are several moving parts which must all work together so hold on to your hat!

1. A `Spark.Dsl.Entity` struct. This is used to define the strategy DSL
   inside the `strategies` (or `add_ons`) section of the `authentication` DSL.
2. A strategy struct, which stores information about the strategy as
   configured on a resource which must comply with a few rules.
3. An optional transformer, which can be used to manipulate the DSL state of
   the entity and the resource.
4. An optional verifier, which can be used to verify the DSL state of the
   entity and the resource after compilation.
5. The `AshAuthentication.Strategy` protocol, which provides the glue needed
   for everything to wire up and wrappers around the actions needed to run on
   the resource.

We're going to define an extremely dumb strategy which lets anyone with a name
that starts with "Marty" sign in with just their name. Of course you would
never do this in real life, but this isn't real life - it's documentation!

## DSL setup

Let's start by defining a module for our strategy to live in. Let's call it
`OnlyMartiesAtTheParty`:

```elixir
defmodule OnlyMartiesAtTheParty do
  use AshAuthentication.Strategy.Custom
end
```

Sadly, this isn't enough to make the magic happen. We need to define our DSL
entity by adding it to the `use` statement:

```elixir
defmodule OnlyMartiesAtTheParty do
  @entity %Spark.Dsl.Entity{
    name: :only_marty,
    describe: "Strategy which only allows folks whose name starts with \"Marty\" to sign in.",
    examples: [
      """
      only_marty do
        case_sensitive? true
        name_field :name
      end
      """
    ],
    target: __MODULE__,
    args: [{:optional, :name, :marty}],
    schema: [
      name: [
        type: :atom,
        doc: """
        The strategy name.
        """,
        required: true
      ],
      case_sensitive?: [
        type: :boolean,
        doc: """
        Ignore letter case when comparing?
        """,
        required: false,
        default: false
      ],
      name_field: [
        type: :atom,
        doc: """
        The field to check for the users' name.
        """,
        required: true
      ]
    ]
  }

  use AshAuthentication.Strategy.Custom, entity: @entity
end
```

If you haven't you should take a look at the docs for `Spark.Dsl.Entity`, but
here's a brief overview of what each field we've set does:

- `name` is the name for which the helper function will be generated in
  the DSL (ie `only_marty do #... end`).
- `describe` and `examples` are used when generating documentation.
- `target` is the name of the module which defines our entity struct. We've
  set it to `__MODULE__` which means that we'll have to define the struct on
  this module.
- `schema` is a keyword list that defines an options schema. See `Spark.Options`.

> By default the entity is added to the `authentication / strategy` DSL, however
> if you want it in the `authentication / add_ons` DSL instead you can also pass
> `style: :add_on` in the `use` statement.

Next up, we need to define our struct. The struct should have _at least_ the
fields named in the entity schema. Additionally, Ash Authentication requires
that it have a `resource` field which will be set to the module of the resource
it's attached to during compilation.

```elixir
defmodule OnlyMartiesAtTheParty do
  defstruct name: :marty, case_sensitive?: false, name_field: nil, resource: nil

  # ...

  use AshAuthentication.Strategy.Custom, entity: @entity

  # other code elided ...
end
```

Now it would be theoretically possible to add this custom strategies to your app
by adding it to the `extensions` section of your resource:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication, OnlyMartiesAtTheParty],
    domain: MyApp.Accounts

  authentication do
    strategies do
      only_marty do
        name_field :name
      end
    end
  end

  attributes do
    uuid_primary_key
    attribute :name, :string, allow_nil?: false
  end
end
```

## Implementing the `AshAuthentication.Strategy` protocol

The Strategy protocol is used to introspect the strategy so that it can
seamlessly fit in with the rest of Ash Authentication. Here are the key
concepts:

- "phases" - in terms of HTTP, each strategy is likely to have many phases (eg OAuth 2.0's "request" and "callback" phases). Essentially you need one phase for each HTTP endpoint you wish to support with your strategy. In our case we just want one sign in endpoint.
- "actions" - actions are exactly as they sound - Resource actions which can be executed by the strategy, whether generated by the strategy (as in the password strategy) or typed in by the user (as in the OAuth 2.0 strategy). The reason that we wrap the strategy's actions this way is that all the built-in strategies (and we hope yours too) allow the user to customise the name of the actions that it uses. At the very least it should probably append the strategy name to the action. Using `Strategy.action/4` allows us to refer these by a more generic name rather than via the user-specified one (eg `:register` vs `:register_with_password`).
- "routes" - `AshAuthentication.Plug` (or [`AshAuthentication.Phoenix.Router.html`](https://hexdocs.pm/ash_authentication_phoenix/AshAuthentication.Phoenix.Router.html)) will generate routes using `Plug.Router` (or [`Phoenix.Router`](https://hexdocs.pm/phoenix/Phoenix.Router.html)) - the `routes/1` callback is used to retrieve this information from the strategy.

Given this information, let's implement the strategy. It's quite long, so I'm
going to break it up into smaller chunks.

```elixir
defimpl AshAuthentication.Strategy, for: OnlyMartiesAtTheParty do
```

The `name/1` function is used to uniquely identify the strategy. It _must_ be an
atom and _should_ be the same as the path fragment used in the generated routes.

```elixir
  def name(strategy), do: strategy.name
```

Since our strategy only supports sign-in we only need a single `:sign_in` phase
and action.

```elixir
  def phases(_), do: [:sign_in]
  def actions(_), do: [:sign_in]
```

Next we generate the routes for the strategy. Routes _should_ contain the
subject name of the resource being authenticated in case the implementer is
authenticating multiple different resources - eg `User` and `Admin`.

```elixir
  def routes(strategy) do
    subject_name = AshAuthentication.Info.authentication_subject_name!(strategy.resource)

    [
      {"/#{subject_name}/#{strategy.name}", :sign_in}
    ]
  end
```

When generating routes or forms for this phase, what HTTP method should we use?

```elixir
  def method_for_phase(_, :sign_in), do: :post
```

Next up, we write our plug. We take the "name field" from the input params in
the conn and pass them to our sign in action. As long as the action returns
`{:ok, Ash.Resource.record}` or `{:error, any}` then we can just pass it
straight into `store_authentication_result/2` from
`AshAuthentication.Plug.Helpers`.

```elixir
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  def plug(strategy, :sign_in, conn) do
    params = Map.take(conn.params, [to_string(strategy.name_field)])
    result = action(strategy, :sign_in, params, [])
    store_authentication_result(conn, result)
  end
```

Next, we implement our sign in action. We use `Ash.Query` to find all
records whose name field matches the input, then constrain it to only records
whose name field starts with "Marty". Depending on whether the name field has a
unique identity on it we have to deal with it returning zero or more users, or
an error. When it returns a single user we return that user in an ok tuple,
otherwise we return an authentication failure.

In this example we're assuming that there is a default `read` action present on
the resource.

> #### Warning {: .warning}
>
> When it comes to authentication, you never want to reveal to the user what the
> failure was - this helps prevent [enumeration
> attacks](https://www.hacksplaining.com/prevention/user-enumeration).
>
> You can use `AshAuthentication.Errors.AuthenticationFailed` for this purpose
> as it will cause `ash_authentication`, `ash_authentication_phoenix`,
> `ash_graphql` and `ash_json_api` to return the correct HTTP 401 error.

```elixir
  alias AshAuthentication.Errors.AuthenticationFailed
  require Ash.Query
  import Ash.Expr

  def action(strategy, :sign_in, params, options) do
    name_field = strategy.name_field
    name = Map.get(params, to_string(name_field))
    domain = AshAuthentication.Info.domain!(strategy.resource)

    strategy.resource
    |> Ash.Query.filter(expr(^ref(name_field) == ^name))
    |> then(fn query ->
      if strategy.case_sensitive? do
        Ash.Query.filter(query, like(^ref(name_field), "Marty%"))
      else
        Ash.Query.filter(query, ilike(^ref(name_field), "Marty%"))
      end
    end)
    |> domain.read(options)
    |> case do
      {:ok, [user]} ->
        {:ok, user}

      {:ok, []} ->
        {:error, AuthenticationFailed.exception(caused_by: %{reason: :no_user})}

      {:ok, _users} ->
        {:error, AuthenticationFailed.exception(caused_by: %{reason: :too_many_users})}

      {:error, reason} ->
        {:error, AuthenticationFailed.exception(caused_by: %{reason: reason})}
    end
  end
end
```

Lastly, we have to implement the `tokens_required?/1` function. This function
indicates Ash Authentication whether your strategy creates or consumes any
tokens. Since our strategy does not, we can simply return false:

```elixir
def tokens_required?(_), do: false
```

## Bonus round - transformers and verifiers

In some cases it may be required for your strategy to modify it's own
configuration or that of the whole resource at compile time. For that you can
define the `transform/2` callback on your strategy module.

At the very least it is good practice to call
`AshAuthentication.Strategy.Custom.Helpers.register_strategy_actions/3` so that
Ash Authentication can keep track of which actions are related to which
strategies and `AshAuthentication.Strategy.Custom.Helpers` is automatically
imported by `use AshAuthentication.Strategy.Custom` for this purpose.

### Transformers

For simple cases where you're just transforming the strategy you can just return
the modified strategy and the DSL will be updated accordingly. For example if
you wanted to generate the name of an action if the user hasn't specified it:

```elixir
def transform(strategy, _dsl_state) do
  {:ok, Map.put_new(strategy, :sign_in_action_name, :"sign_in_with_#{strategy.name}")}
end
```

In some cases you may want to modify the strategy and the resources DSL. In
this case you can return the newly mutated DSL state in an ok tuple or an error
tuple, preferably containing a `Spark.Error.DslError`. For example if we wanted
to build a sign in action for `OnlyMartiesAtTheParty` to use:

```elixir
def transform(strategy, dsl_state) do
  strategy = Map.put_new(strategy, :sign_in_action_name, :"sign_in_with_#{strategy.name}")

  sign_in_action =
    Spark.Dsl.Transformer.build_entity(Ash.Resource.Dsl, [:actions], :read,
      name: strategy.sign_in_action_name,
      accept: [strategy.name_field],
      get?: true
    )

  dsl_state =
    dsl_state
    |> Spark.Dsl.Transformer.add_entity([:actions], sign_in_action)
    |> put_strategy(strategy)
    |> then(fn dsl_state ->
      register_strategy_actions([strategy.sign_in_action_name], dsl_state, strategy)
    end)

  {:ok, dsl_state}
end
```

Transformers can also be used to validate user input or even directly add code
to the resource. See the docs for `Spark.Dsl.Transformer` for more information.

### Verifiers

We also support a variant of transformers which run in the new `@after_verify`
compile hook provided by Elixir 1.14. This is a great place to put checks
to make sure that the user's configuration makes sense without adding any
compile-time dependencies between modules which may cause compiler deadlocks.

For example, verifying that the "name" attribute contains "marty" (why you would
do this I don't know but I'm running out of sensible examples):

```elixir
def verify(strategy, _dsl_state) do
  if String.contains?(to_string(strategy.name_field), "marty") do
    :ok
  else
    {:error,
      Spark.Error.DslError.exception(
        path: [:authentication, :strategies, :only_marties],
        message: "Option `name_field` must contain \"marty\""
      )}
  end
end
```

## Summary

You should now have all the tools you need to build custom strategies - and in
fact the strategies provided by Ash Authentication are built using this system.

If there is functionality or documentation missing please [raise an
issue](https://github.com/team-alembic/ash_authentication/issues/new) and we'll
take a look at it.

Go forth and strategise!
