add_library(
  fuzzuf_core_nautilus
  OBJECT
  grammartec/context.cpp
  grammartec/rule.cpp
  grammartec/chunkstore.cpp
  grammartec/recursion_info.cpp
  grammartec/mutator.cpp
  grammartec/tree.cpp
  fuzzer/mutation_hierarflow_routines.cpp
  fuzzer/update_hierarflow_routines.cpp
  fuzzer/state.cpp
  fuzzer/queue.cpp
  fuzzer/fuzzer.cpp
  fuzzer/other_hierarflow_routines.cpp
)

target_include_directories(
  fuzzuf_core_nautilus
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_nautilus
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_nautilus
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_nautilus
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_nautilus
  ${FUZZUF_LIBRARIES}
)


