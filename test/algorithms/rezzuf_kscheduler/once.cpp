/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
#define BOOST_TEST_MODULE algorithms.rezzuf_kscheduler.cli
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <boost/test/unit_test.hpp>

#include "fuzzuf/cli/create_fuzzer_instance_from_argv.hpp"
#include "fuzzuf/tests/standard_test_dirs.hpp"
#include "fuzzuf/utils/count_regular_files.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/kscheduler/gen_dyn_weight.hpp"
#include "fuzzuf/utils/copy.hpp"

BOOST_AUTO_TEST_CASE(ExecuteAFLKSchedulerFromCLI) {
  // Setup root directory
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_STANDARD_TEST_DIRS
//  FUZZUF_STANDARD_TEST_DIRS
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  BOOST_TEST_CHECKPOINT("before init state");

  fs::current_path( root_dir );
  fuzzuf::utils::copy( fs::path( TEST_BINARY_DIR )/"put"/"kscheduler"/"katz_cent", root_dir/"katz_cent" );
  fuzzuf::utils::copy( fs::path( TEST_BINARY_DIR )/"put"/"kscheduler"/"border_edges", root_dir/"border_edges" );
  fuzzuf::utils::copy( fs::path( TEST_BINARY_DIR )/"put"/"kscheduler"/"child_node", root_dir/"child_node" );
  fuzzuf::utils::copy( fs::path( TEST_BINARY_DIR )/"put"/"kscheduler"/"parent_node", root_dir/"parent_node" );
  fuzzuf::utils::copy( fs::path( TEST_BINARY_DIR )/"put"/"kscheduler"/"graph_data_pack", root_dir/"graph_data_pack" );
  fuzzuf::utils::kscheduler::GenDynWeight gen_dyn_weight(
    FUZZUF_KSCHEDULER_SCRIPT_DIR "/gen_dyn_weight.py",
    FUZZUF_NK_DIR
  );

  for( const auto &e: fs::directory_iterator( fs::path( TEST_SOURCE_DIR )/"put"/"kscheduler"/"seeds" ) ) {
    fuzzuf::utils::copy( e.path(), input_dir );
  }

  BOOST_TEST_CHECKPOINT("initialized dirs");

  const char *argv[] = {"fuzzuf",
                        "rezzuf_kscheduler",
                        "-i",
                        input_dir.c_str(),
                        "-o",
                        output_dir.c_str(),
			"--forksrv",
			"false",
			"-s",
                        TEST_BINARY_DIR "/put/kscheduler/kscheduler-easy_to_branch",
			"@@",
                        nullptr};
  constexpr int argc = 11;
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv(argc, argv);

  BOOST_TEST_CHECKPOINT("created fuzzer");

  fuzzer->OneLoop();

  // At least one crash input is produced
  BOOST_CHECK_GE(fuzzuf::utils::CountRegularFiles(output_dir / "crashes"), 1);

  BOOST_TEST_CHECKPOINT("done");
}
