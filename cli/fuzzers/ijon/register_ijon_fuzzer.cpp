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

#include "fuzzuf/algorithms/ijon/ijon_fuzzer.hpp"
#include "fuzzuf/cli/fuzzer/ijon/build_ijon_fuzzer_from_args.hpp"
#include "fuzzuf/cli/fuzzer_builder_register.hpp"

namespace fuzzuf::cli::fuzzer::ijon {

// builder_map.insert is called before main function if the below is declared as
// a global variable and linked as an object file. Conversely, if IJON cannot be
// built in a certain environment, do not compile it into an object file to
// prevent IJON from being registered by accident.
static FuzzerBuilderRegister global_ijon_register(
    "ijon", BuildIJONFuzzerFromArgs<fuzzuf::fuzzer::Fuzzer,
                                    algorithm::ijon::IJONFuzzer>);

}  // namespace fuzzuf::cli::fuzzer::ijon
