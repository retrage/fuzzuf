/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
/**
 * @file executor.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/executor/executor.hpp"

#include <cassert>
#include <cstddef>
#include <filesystem>
#include <memory>

#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/is_executable.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/utils/which.hpp"
#include "fuzzuf/utils/workspace.hpp"

namespace fuzzuf::executor {

Executor::Executor(const std::vector<std::string> &argv, u32 exec_timelimit_ms,
                   u64 exec_memlimit, const std::string path_str_to_write_input)
    : argv(argv),
      exec_timelimit_ms(exec_timelimit_ms),
      exec_memlimit(exec_memlimit),
      // Although cargv refers path_str_to_write_input.c_str(),
      // since the lifetime of fs::path::c_str is non deterministic, avoid using
      // it.
      path_str_to_write_input(path_str_to_write_input),
      child_pid(0),
      input_fd(-1),
      null_fd(-1),
      stdin_mode(false) {}

/// @brief Checks if given file is a PUT binary.
/// @param shm_env_var Environment variable for shared memory ID used in
/// instrumented PUT.
void Executor::CheckBinary(const char *shm_env_var) {
  if (!cargv[0]) {
    ABORT("BUG: Binary name is NULL");
  }

  // Assuming the target executable path is cargv[0].
  // This is not always correct if the executor uses a proxy application.
  auto target_path = fuzzuf::utils::which(cargv[0]);
  if (!fuzzuf::utils::is_executable(target_path)) {
    ABORT("Program '%s' not found or not executable", target_path.c_str());
  }

  std::uintmax_t file_size = fs::file_size(target_path);
  if (file_size < 4) {
    ABORT("Program '%s' is too small", target_path.c_str());
  }

  auto mapped = fuzzuf::utils::map_file(target_path, O_RDONLY, true);

  std::vector<std::uint8_t> shebang_signature{'#', '!'};
  if (std::equal(mapped.begin(), mapped.begin() + shebang_signature.size(),
                 shebang_signature.begin(), shebang_signature.end())) {
    MSG("\n" cLRD "[-] " cRST
        "Oops, the target binary looks like a shell script. Some build "
        "systems will\n"
        "    sometimes generate shell stubs for dynamically linked programs; "
        "try static\n"
        "    library mode (./configure --disable-shared) if that's the "
        "case.\n\n"

        "    Another possible cause is that you are actually trying to use a "
        "shell\n"
        "    wrapper around the fuzzed component. Invoking shell can slow "
        "down the\n"
        "    fuzzing process by a factor of 20x or more; it's best to write "
        "the wrapper\n"
        "    in a compiled language instead.\n");

    ABORT("Program '%s' is a shell script", target_path.c_str());
  }

  std::vector<std::uint8_t> elf_signature{0x7f, 'E', 'L', 'F'};
  if (!std::equal(mapped.begin(), mapped.begin() + elf_signature.size(),
                  elf_signature.begin(), elf_signature.end())) {
    ABORT("Program '%s' is not an ELF binary", target_path.c_str());
  }

  // FIXME: Checking if shared memory ID string exists in the target executable
  // is not 'correct' way.
  if (shm_env_var && !memmem(reinterpret_cast<std::uint8_t *>(&mapped[0]),
                             file_size, shm_env_var, strlen(shm_env_var) + 1)) {
    MSG("\n" cLRD "[-] " cRST
        "Looks like the target binary is not instrumented! The fuzzer depends "
        "on\n"
        "    compile-time instrumentation to isolate interesting test cases "
        "while\n"
        "    mutating the input data. For more information, and for tips on "
        "how to\n"
        "    instrument binaries, please see docs.\n\n"

        "    When source code is not available, you may be able to leverage "
        "QEMU\n"
        "    mode support. Consult the README.md for tips on how to enable "
        "this.\n");

    ABORT("No instrumentation detected");
  }
}

/**
 * Precondition:
 *  - A file can be created at path path_str_to_write_input.
 * Postcondition:
 *  - enable input_fd member. In othe word, open the file specified by
 * path_str_to_write_input, then assign the file descriptor to input_fd.
 *  - enable null_fd member. In other word, open "/dev/null", then assign the
 * file descriptor to null_fd.
 */
void Executor::OpenExecutorDependantFiles() {
  input_fd = fuzzuf::utils::OpenFile(path_str_to_write_input,
                                     O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  null_fd = fuzzuf::utils::OpenFile("/dev/null", O_RDONLY | O_CLOEXEC);
  assert(input_fd > -1 && null_fd > -1);
}

/**
 * Precondition:
 *  - input_fd is a file descriptor that points a file of fuzz.
 * Postcondition:
 *  - Write out the data pointed by buf to the file pointed by input_fd.
 *  - The written out file only contains data pointed by buf.
 *  - The size of written out file is smaller or equal to the value specified by
 * len.
 *  - Seek "file position indicator" to head of the file for reading the file
 * from target process. Check if the current execution path brings anything new
 * to the table. Update virgin bits to reflect the finds. Returns 1 if the only
 * change is the hit-count for a particular tuple; 2 if there are new tuples
 * seen. Updates the map, so subsequent calls will always return 0.
 *
 * This function is called after every exec() on a fairly large buffer, so
 * it needs to be fast. We do this in 32-bit and 64-bit flavors.
 */
void Executor::WriteTestInputToFile(const u8 *buf, u32 len) {
  assert(input_fd > -1);

  fuzzuf::utils::SeekFile(input_fd, 0, SEEK_SET);
  fuzzuf::utils::WriteFile(input_fd, buf, len);
  if (fuzzuf::utils::TruncateFile(input_fd, len)) ERROR("ftruncate() failed");
  fuzzuf::utils::SeekFile(input_fd, 0, SEEK_SET);
}

/*
 * Postcondition:
 *  - When child_pid has valid value,
 *      - Kill the process specified by child_pid
 *      - Then, inactivate the value of child_pid (for fail-safe)
 *  Note that it doesn't call waitpid (It is expected to be called in different
 * location)
 */
void Executor::KillChildWithoutWait() {
  if (child_pid > 0) {
    kill(child_pid, SIGKILL);
    child_pid = -1;
  }
}

}  // namespace fuzzuf::executor
