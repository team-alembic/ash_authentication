spark_locals_without_parens = [
  api: 1,
  confirmation_required?: 1,
  hash_provider: 1,
  hashed_password_field: 1,
  identity_field: 1,
  password_confirmation_field: 1,
  password_field: 1,
  read_action_name: 1,
  register_action_name: 1,
  sign_in_action_name: 1,
  subject_name: 1
]

[
  import_deps: [:ash, :spark],
  inputs: [
    "*.{ex,exs}",
    "{dev,config,lib,test}/**/*.{ex,exs}"
  ],
  plugins: [Spark.Formatter],
  export: [
    locals_without_parens: spark_locals_without_parens
  ]
]
