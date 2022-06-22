add_library(
  fuzzuf_core_libfuzzer_common
  STATIC
  dictionary.cpp
  input_info.cpp
  #select_seed.cpp
  test_utils.cpp
  utils.cpp
  config.cpp
  fuzzer.cpp
  options.cpp
  state.cpp
  trace.cpp
)

target_include_directories(
  fuzzuf_core_libfuzzer_common
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_libfuzzer_common
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_libfuzzer_common
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_libfuzzer_common
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_libfuzzer_common
  ${FUZZUF_LIBRARIES}
)


