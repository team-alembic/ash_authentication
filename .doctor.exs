%Doctor.Config{
  ignore_modules: [
    ~r/^Inspect\./,
    ~r/.Plug$/,
    AshAuthentication.InfoGenerator,
    AshAuthentication.Plug.Macros
  ],
  ignore_paths: [],
  min_module_doc_coverage: 40,
  min_module_spec_coverage: 0,
  min_overall_doc_coverage: 50,
  min_overall_spec_coverage: 0,
  min_overall_moduledoc_coverage: 100,
  exception_moduledoc_required: true,
  raise: false,
  reporter: Doctor.Reporters.Full,
  struct_type_spec_required: true,
  umbrella: false
}
