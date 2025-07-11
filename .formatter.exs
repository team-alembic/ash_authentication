spark_locals_without_parens = [
  access_token_attribute_name: 1,
  access_token_expires_at_attribute_name: 1,
  action_name: 1,
  api_key: 0,
  api_key: 1,
  api_key: 2,
  api_key_hash_attribute: 1,
  api_key_relationship: 1,
  apple: 0,
  apple: 1,
  apple: 2,
  apply_on_password_change?: 1,
  argument_name: 1,
  auth0: 0,
  auth0: 1,
  auth0: 2,
  auth_method: 1,
  authorization_params: 1,
  authorize_url: 1,
  auto_confirm_actions: 1,
  base_url: 1,
  client_authentication_method: 1,
  client_id: 1,
  client_secret: 1,
  code_verifier: 1,
  confirm_action_name: 1,
  confirm_on_create?: 1,
  confirm_on_update?: 1,
  confirmation: 0,
  confirmation: 1,
  confirmation: 2,
  confirmation_required?: 1,
  confirmed_at_field: 1,
  created_at_attribute_name: 1,
  destroy_action_name: 1,
  domain: 1,
  enabled?: 1,
  exclude_purposes: 1,
  expunge_expired_action_name: 1,
  expunge_interval: 1,
  get_by_subject_action_name: 1,
  get_changes_action_name: 1,
  get_token_action_name: 1,
  github: 0,
  github: 1,
  github: 2,
  google: 0,
  google: 1,
  google: 2,
  hash_provider: 1,
  hashed_password_field: 1,
  icon: 1,
  id_token_signed_response_alg: 1,
  id_token_ttl_seconds: 1,
  identity_field: 1,
  identity_relationship_name: 1,
  identity_relationship_user_id_attribute: 1,
  identity_resource: 1,
  include_purposes: 1,
  inhibit_updates?: 1,
  is_revoked_action_name: 1,
  log_out_everywhere: 0,
  log_out_everywhere: 1,
  log_out_everywhere: 2,
  lookup_action_name: 1,
  magic_link: 0,
  magic_link: 1,
  magic_link: 2,
  monitor_fields: 1,
  name: 1,
  nonce: 1,
  oauth2: 0,
  oauth2: 1,
  oauth2: 2,
  oidc: 0,
  oidc: 1,
  oidc: 2,
  openid_configuration: 1,
  openid_configuration_uri: 1,
  password: 0,
  password: 1,
  password: 2,
  password_confirmation_field: 1,
  password_field: 1,
  password_reset_action_name: 1,
  prevent_hijacking?: 1,
  private_key: 1,
  private_key_id: 1,
  private_key_path: 1,
  read_action_name: 1,
  read_expired_action_name: 1,
  redirect_uri: 1,
  refresh_token_attribute_name: 1,
  register_action_accept: 1,
  register_action_name: 1,
  registration_enabled?: 1,
  request_action_name: 1,
  request_password_reset_action_name: 1,
  require_confirmed_with: 1,
  require_interaction?: 1,
  require_token_presence_for_authentication?: 1,
  resettable: 0,
  resettable: 1,
  revoke_all_stored_for_subject_action_name: 1,
  revoke_jti_action_name: 1,
  revoke_token_action_name: 1,
  select_for_senders: 1,
  sender: 1,
  session_identifier: 1,
  sign_in_action_name: 1,
  sign_in_enabled?: 1,
  sign_in_token_lifetime: 1,
  sign_in_tokens_enabled?: 1,
  sign_in_with_token_action_name: 1,
  signing_algorithm: 1,
  signing_secret: 1,
  single_use_token?: 1,
  site: 1,
  slack: 0,
  slack: 1,
  slack: 2,
  store_all_tokens?: 1,
  store_changes_action_name: 1,
  store_token_action_name: 1,
  strategy_attribute_name: 1,
  subject_name: 1,
  team_id: 1,
  token_lifetime: 1,
  token_param_name: 1,
  token_resource: 1,
  token_url: 1,
  trusted_audiences: 1,
  uid_attribute_name: 1,
  upsert_action_name: 1,
  user_id_attribute_name: 1,
  user_relationship_name: 1,
  user_resource: 1,
  user_url: 1
]

[
  import_deps: [:ash, :ash_json_api, :ash_graphql, :spark],
  inputs: [
    "*.{ex,exs}",
    "{dev,config,lib,test}/**/*.{ex,exs}"
  ],
  plugins: [Spark.Formatter],
  locals_without_parens: spark_locals_without_parens,
  export: [
    locals_without_parens: spark_locals_without_parens
  ]
]
