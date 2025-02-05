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
#pragma once

#include <functional>
#include <memory>

namespace fuzzuf::fuzzer {

class Fuzzer {
 public:
  virtual ~Fuzzer() {}

  virtual void OneLoop(void) {}

  // do not call non aync-signal-safe functions inside because this function can
  // be called during signal handling
  virtual void ReceiveStopSignal(void) = 0;

  virtual bool ShouldEnd(void) { return false; }
};

}  // namespace fuzzuf::fuzzer
