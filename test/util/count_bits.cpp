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
#define BOOST_TEST_MODULE util.count_bits
#include <array>
#include <boost/test/unit_test.hpp>
#include <iostream>

#include "fuzzuf/utils/common.hpp"
#include "random_data.hpp"
BOOST_AUTO_TEST_CASE(UtilCountBits) {
  BOOST_CHECK_EQUAL(
      (fuzzuf::utils::CountBits(random_data1.data(), random_data1.size())),
      262309);
  BOOST_CHECK_EQUAL(
      (fuzzuf::utils::CountBits(random_data2.data(), random_data2.size())),
      1892);
  BOOST_CHECK_EQUAL(
      (fuzzuf::utils::CountBits(random_data3.data(), random_data3.size())),
      448);
}
