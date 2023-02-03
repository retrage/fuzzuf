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

#ifndef FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_TESTCASE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_TESTCASE_HPP

#include <memory>

#include "fuzzuf/algorithms/afl/afl_testcase.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"
#include "fuzzuf/exec_input/on_disk_exec_input.hpp"

namespace fuzzuf::algorithm::mopt {

using fuzzuf::exec_input::OnDiskExecInput;

struct MOptTestcase : public afl::AFLTestcase {
  using Tag = fuzzuf::algorithm::mopt::option::MOptTag;

  explicit MOptTestcase(std::shared_ptr<OnDiskExecInput> input);
  ~MOptTestcase();
};

}  // namespace fuzzuf::algorithm::mopt

#endif
