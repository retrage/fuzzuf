add_custom_target(
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  COMMAND ${CMAKE_COMMAND} -E
  copy ${CMAKE_BINARY_DIR}/tools/algorithms/eclipser/instrumentor/branch-x86/qemu-trace-branch-x86-prefix/bin/qemu-i386 ${CMAKE_BINARY_DIR}/test/algorithms/eclipser/qemu-trace-branch-x86
  DEPENDS qemu-trace-branch-x86
)
add_custom_target(
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  COMMAND ${CMAKE_COMMAND} -E
  copy ${CMAKE_BINARY_DIR}/tools/algorithms/eclipser/instrumentor/branch-x86_64/qemu-trace-branch-x86_64-prefix/bin/qemu-x86_64 ${CMAKE_BINARY_DIR}/test/algorithms/eclipser/qemu-trace-branch-x64
  DEPENDS qemu-trace-branch-x86_64
)
add_custom_target(
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  COMMAND ${CMAKE_COMMAND} -E
  copy ${CMAKE_BINARY_DIR}/tools/algorithms/eclipser/instrumentor/coverage-x86/qemu-trace-coverage-x86-prefix/bin/qemu-i386 ${CMAKE_BINARY_DIR}/test/algorithms/eclipser/qemu-trace-coverage-x86
  DEPENDS qemu-trace-coverage-x86
)
add_custom_target(
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
  COMMAND ${CMAKE_COMMAND} -E
  copy ${CMAKE_BINARY_DIR}/tools/algorithms/eclipser/instrumentor/coverage-x86_64/qemu-trace-coverage-x86_64-prefix/bin/qemu-x86_64 ${CMAKE_BINARY_DIR}/test/algorithms/eclipser/qemu-trace-coverage-x64
  DEPENDS qemu-trace-coverage-x86_64
)
add_executable( test-algorithms-eclipser-executor executor.cpp )
target_link_libraries(
  test-algorithms-eclipser-executor
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-executor
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-executor
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-executor
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-executor
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-executor
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.executor" COMMAND test-algorithms-eclipser-executor )

add_executable( test-algorithms-eclipser-seed seed.cpp )
target_link_libraries(
  test-algorithms-eclipser-seed
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-seed
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-seed
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-seed
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-seed
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-seed
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.seed" COMMAND test-algorithms-eclipser-seed )

add_executable( test-algorithms-eclipser-linear_equation linear_equation.cpp )
target_link_libraries(
  test-algorithms-eclipser-linear_equation
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-linear_equation
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-linear_equation
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-linear_equation
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-linear_equation
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-linear_equation
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.linear_equation" COMMAND test-algorithms-eclipser-linear_equation )

add_executable( test-algorithms-eclipser-linear_inequality linear_inequality.cpp )
target_link_libraries(
  test-algorithms-eclipser-linear_inequality
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-linear_inequality
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-linear_inequality
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-linear_inequality
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-linear_inequality
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-linear_inequality
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.linear_inequality" COMMAND test-algorithms-eclipser-linear_inequality )

add_executable( test-algorithms-eclipser-monotonicity monotonicity.cpp )
target_link_libraries(
  test-algorithms-eclipser-monotonicity
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-monotonicity
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-monotonicity
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-monotonicity
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-monotonicity
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-monotonicity
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.monotonicity" COMMAND test-algorithms-eclipser-monotonicity )

add_executable( test-algorithms-eclipser-branch_tree branch_tree.cpp )
target_link_libraries(
  test-algorithms-eclipser-branch_tree
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-branch_tree
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-branch_tree
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-branch_tree
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-branch_tree
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-branch_tree
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.branch_tree" COMMAND test-algorithms-eclipser-branch_tree )

add_executable( test-algorithms-eclipser-gray_concolic gray_concolic.cpp )
target_link_libraries(
  test-algorithms-eclipser-gray_concolic
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-gray_concolic
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-gray_concolic
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-gray_concolic
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-gray_concolic
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-gray_concolic
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.gray_concolic" COMMAND test-algorithms-eclipser-gray_concolic )

add_executable( test-algorithms-eclipser-fuzz_stdin fuzz_stdin.cpp )
target_link_libraries(
  test-algorithms-eclipser-fuzz_stdin
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-fuzz_stdin
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-fuzz_stdin
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-fuzz_stdin
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-fuzz_stdin
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-fuzz_stdin
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.fuzz_stdin" COMMAND test-algorithms-eclipser-fuzz_stdin )

add_executable( test-algorithms-eclipser-fuzz_linear fuzz_linear.cpp )
target_link_libraries(
  test-algorithms-eclipser-fuzz_linear
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-fuzz_linear
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-fuzz_linear
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-fuzz_linear
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-fuzz_linear
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-fuzz_linear
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.fuzz_linear" COMMAND test-algorithms-eclipser-fuzz_linear )

add_executable( test-algorithms-eclipser-fuzz_monoton fuzz_monoton.cpp )
target_link_libraries(
  test-algorithms-eclipser-fuzz_monoton
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-fuzz_monoton
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-fuzz_monoton
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-fuzz_monoton
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-fuzz_monoton
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-fuzz_monoton
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.fuzz_monoton" COMMAND test-algorithms-eclipser-fuzz_monoton )

add_executable( test-algorithms-eclipser-cli_parser cli_parser.cpp )
target_link_libraries(
  test-algorithms-eclipser-cli_parser
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-cli_parser
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-cli_parser
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-cli_parser
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-cli_parser
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-cli_parser
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.cli_parser" COMMAND test-algorithms-eclipser-cli_parser )

add_executable( test-algorithms-eclipser-cli cli.cpp )
target_link_libraries(
  test-algorithms-eclipser-cli
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-algorithms-eclipser-cli
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-algorithms-eclipser-cli
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-algorithms-eclipser-cli
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_dependencies(
  test-algorithms-eclipser-cli
  test-algorithms-eclipser-copy-qemu-trace-branch-x86
  test-algorithms-eclipser-copy-qemu-trace-branch-x86_64
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86
  test-algorithms-eclipser-copy-qemu-trace-coverage-x86_64
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-algorithms-eclipser-cli
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
add_test( NAME "algorithms.eclipser.cli" COMMAND test-algorithms-eclipser-cli )
