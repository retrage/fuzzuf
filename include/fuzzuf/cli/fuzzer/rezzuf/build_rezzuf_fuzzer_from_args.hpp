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

#ifndef FUZZUF_INCLUDE_CLI_FUZZER_REZZUF_BUILD_REZZUF_FROM_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_FUZZER_REZZUF_BUILD_REZZUF_FROM_ARGS_HPP

#include "fuzzuf/algorithms/afl/afl_havoc_case_distrib.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_option.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_havoc.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_option.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_state.hpp"
#include "fuzzuf/cli/fuzzer/rezzuf/check_parallel_mode_args.hpp"
#include "fuzzuf/cli/fuzzer_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/linux_fork_server_executor.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/executor/qemu_executor.hpp"
#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/optimizer/slopt/slopt_optimizer.hpp"
#include "fuzzuf/utils/optparser.hpp"
#include "fuzzuf/utils/parallel_mode.hpp"
#include "fuzzuf/utils/workspace.hpp"
#ifdef __aarch64__
#include "fuzzuf/executor/coresight_executor.hpp"
#endif
#include <boost/program_options.hpp>

namespace fuzzuf::cli::fuzzer::rezzuf {

namespace po = boost::program_options;

struct RezzufFuzzerOptions {
  bool forksrv;                        // Optional
  std::vector<std::string> dict_file;  // Optional
  bool frida_mode;                     // Optional
  std::string schedule;                // Optional
  std::string instance_id;             // Optional
  utils::ParallelModeT parallel_mode =
      utils::ParallelModeT::SINGLE;  // Optional
  // Default values
  RezzufFuzzerOptions() : forksrv(true), frida_mode(false), schedule("fast"){};
};

// Fuzzer specific help
// TODO: Provide better help message
static void usage(po::options_description &desc) {
  std::cout << "Help:" << std::endl;
  std::cout << desc << std::endl;
  exit(1);
}

// Used only for CLI
template <class TFuzzer, class TAFLFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildRezzufFuzzerFromArgs(
    FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
  po::positional_options_description pargs_desc;
  pargs_desc.add("fuzzer", 1);
  pargs_desc.add("pargs", -1);

  RezzufFuzzerOptions rezzuf_options;

  po::options_description fuzzer_desc("Rezzuf options");
  std::vector<std::string> pargs;
  fuzzer_desc.add_options()(
      "forksrv",
      po::value<bool>(&rezzuf_options.forksrv)
          ->default_value(rezzuf_options.forksrv),
      "Enable/disable fork server mode. default is true.")(
      "dict_file,x",
      po::value<std::vector<std::string>>(&rezzuf_options.dict_file)
          ->composing(),
      "Load additional dictionary file.")
      // If you want to add fuzzer specific options, add options here
      ("pargs", po::value<std::vector<std::string>>(&pargs),
       "Specify PUT and args for PUT.")(
          "frida",
          po::value<bool>(&rezzuf_options.frida_mode)
              ->default_value(rezzuf_options.frida_mode),
          "Enable/disable frida mode. Default to false.")(
          "schedule,p",
          po::value<std::string>(&rezzuf_options.schedule)
              ->default_value(rezzuf_options.schedule),
          "Power schedule to use. Available values are:\n"
          "fast (default), coe, explore, lin, quad, exploit")(
          "parallel-deterministic,M",
          po::value<std::string>(&rezzuf_options.instance_id),
          "distributed mode (see docs/algorithms/afl/parallel_fuzzing.md)")(
          "parallel-random,S",
          po::value<std::string>(&rezzuf_options.instance_id),
          "distributed mode (see docs/algorithms/afl/parallel_fuzzing.md)");

  po::variables_map vm;
  po::store(
      po::command_line_parser(fuzzer_args.argc, fuzzer_args.argv)
          .options(fuzzer_args.global_options_description.add(fuzzer_desc))
          .positional(pargs_desc)
          .run(),
      vm);
  po::notify(vm);

  if (global_options.help) {
    fuzzuf::cli::fuzzer::rezzuf::usage(fuzzer_args.global_options_description);
  }

  CheckParallelModeArgs(vm, rezzuf_options, global_options);

  using fuzzuf::algorithm::afl::option::GetMemLimit;
  using fuzzuf::algorithm::rezzuf::option::RezzufTag;

  u32 mem_limit =
      global_options.exec_memlimit.value_or(GetMemLimit<RezzufTag>());
  if (rezzuf_options.frida_mode) {
    setenv("__AFL_DEFER_FORKSRV", "1", 1);
    fs::path frida_bin =
        fs::path(fuzzer_args.argv[0]).parent_path() / "afl-frida-trace.so";
    setenv("LD_PRELOAD", frida_bin.c_str(), 1);

    if (mem_limit > 0) {
      struct stat statbuf;
      if ((stat(frida_bin.c_str(), &statbuf)) == -1) {
        std::cerr
            << cLRD << "[-] File afl-frida-trace.so not found\n"
            << "    Build one first with cmake where -DENABLE_FRIDA_TRACE=1"
            << cRST << std::endl;
      }
      // Need to add the size of the library
      mem_limit += statbuf.st_size;
    }
  }

  PutArgs put(pargs);
  try {
    put.Check();
  } catch (const exceptions::cli_error &e) {
    std::cerr << "[!] " << e.what() << std::endl;
    std::cerr << "\tat " << e.file << ":" << e.line << std::endl;
    fuzzuf::cli::fuzzer::rezzuf::usage(fuzzer_args.global_options_description);
  }

  // Trace level log
  DEBUG("[*] PUT: put = [");
  for (auto v : put.Args()) {
    DEBUG("\t\"%s\",", v.c_str());
  }
  DEBUG("    ]");

  using fuzzuf::algorithm::afl::option::GetExecTimeout;
  using fuzzuf::algorithm::rezzuf::RezzufSetting;

  // Create RezzufSetting

  fuzzuf::algorithm::aflfast::option::Schedule schedule;
  if (!rezzuf_options.schedule.compare("fast")) {
    schedule = fuzzuf::algorithm::aflfast::option::FAST;
  } else if (!rezzuf_options.schedule.compare("coe")) {
    schedule = fuzzuf::algorithm::aflfast::option::COE;
  } else if (!rezzuf_options.schedule.compare("explore")) {
    schedule = fuzzuf::algorithm::aflfast::option::EXPLORE;
  } else if (!rezzuf_options.schedule.compare("lin")) {
    schedule = fuzzuf::algorithm::aflfast::option::LIN;
  } else if (!rezzuf_options.schedule.compare("quad")) {
    schedule = fuzzuf::algorithm::aflfast::option::QUAD;
  } else if (!rezzuf_options.schedule.compare("exploit")) {
    schedule = fuzzuf::algorithm::aflfast::option::EXPLOIT;
  } else {
    std::cout << cLRD "[-] Unknown power schedule!"
              << "(" << rezzuf_options.schedule << ")" cRST << std::endl;
    std::exit(1);
  }

  auto setting = std::make_shared<const RezzufSetting>(
      put.Args(), global_options.in_dir, global_options.out_dir,
      global_options.exec_timelimit_ms.value_or(GetExecTimeout<RezzufTag>()),
      mem_limit, rezzuf_options.forksrv,
      /* dumb_mode */ false,  // FIXME: add dumb_mode
      global_options.cpuid_to_bind, schedule, rezzuf_options.schedule);

  // NativeLinuxExecutor needs the directory specified by "out_dir" to be
  // already set up so we need to create the directory first, and then
  // initialize Executor
  fuzzuf::utils::SetupDirs(setting->out_dir.string());

  using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
  using fuzzuf::algorithm::afl::option::GetMapSize;
  using fuzzuf::cli::ExecutorKind;

  std::shared_ptr<TExecutor> executor;
  switch (global_options.executor) {
    case ExecutorKind::NATIVE: {
      auto nle = std::make_shared<fuzzuf::executor::NativeLinuxExecutor>(
          setting->argv, setting->exec_timelimit_ms, setting->exec_memlimit,
          setting->forksrv, setting->out_dir / GetDefaultOutfile<RezzufTag>(),
          GetMapSize<RezzufTag>(),  // afl_shm_size
          0                         // bb_shm_size
      );
      executor = std::make_shared<TExecutor>(std::move(nle));
      break;
    }

    case ExecutorKind::FORKSERVER: {
      auto lfe = std::make_shared<fuzzuf::executor::LinuxForkServerExecutor>(
          fuzzuf::executor::LinuxForkServerExecutorParameters()
              .set_argv(setting->argv)
              .set_exec_timelimit_ms(setting->exec_timelimit_ms)
              .set_exec_memlimit(setting->exec_memlimit)
              .set_path_to_write_input(setting->out_dir /
                                       GetDefaultOutfile<RezzufTag>())
              .set_afl_shm_size(GetMapSize<RezzufTag>())  // afl_shm_size
              .move());
      executor = std::make_shared<TExecutor>(std::move(lfe));
      break;
    }

    case ExecutorKind::QEMU: {
      // NOTE: Assuming GetMapSize<RezzufTag>() ==
      // QEMUExecutor::QEMU_SHM_SIZE
      auto qe = std::make_shared<fuzzuf::executor::QEMUExecutor>(
          global_options.proxy_path.value(), setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit, setting->forksrv,
          setting->out_dir / GetDefaultOutfile<RezzufTag>());
      executor = std::make_shared<TExecutor>(std::move(qe));
      break;
    }

#ifdef __aarch64__
    case ExecutorKind::CORESIGHT: {
      auto cse = std::make_shared<fuzzuf::executor::CoreSightExecutor>(
          global_options.proxy_path.value(), setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit, setting->forksrv,
          setting->out_dir / GetDefaultOutfile<RezzufTag>(),
          GetMapSize<RezzufTag>()  // afl_shm_size
      );
      executor = std::make_shared<TExecutor>(std::move(cse));
      break;
    }
#endif

    default:
      EXIT("Unsupported executor: '%s'", global_options.executor.c_str());
  }

  using algorithm::afl::option::GetHavocStackPow2;
  using algorithm::afl::option::GetMaxFile;
  using algorithm::aflplusplus::havoc::AFLPLUSPLUS_NUM_CASE;

  std::unique_ptr<optimizer::HavocOptimizer> havoc_optimizer(
      new optimizer::slopt::SloptOptimizer(AFLPLUSPLUS_NUM_CASE,
                                           GetMaxFile<RezzufTag>(),
                                           GetHavocStackPow2<RezzufTag>()));

  // Create RezzufState
  using fuzzuf::algorithm::rezzuf::RezzufState;
  auto state = std::make_unique<RezzufState>(setting, executor,
                                             std::move(havoc_optimizer));

  state->skip_deterministic = true;

  // Load dictionary
  for (const auto &d : rezzuf_options.dict_file) {
    using fuzzuf::algorithm::afl::dictionary::AFLDictData;

    const std::function<void(std::string &&)> f = [](std::string s) {
      ERROR("Dictionary error: %s", s.c_str());
    };

    fuzzuf::algorithm::afl::dictionary::load(d, state->extras, false, f);
  }
  fuzzuf::algorithm::afl::dictionary::SortDictByLength(state->extras);

  if (rezzuf_options.parallel_mode != utils::ParallelModeT::SINGLE) {
    state->sync_external_queue = true;
    state->sync_id = rezzuf_options.instance_id;
  }

  return std::unique_ptr<TFuzzer>(
      dynamic_cast<TFuzzer *>(new TAFLFuzzer(std::move(state))));
}

}  // namespace fuzzuf::cli::fuzzer::rezzuf

#endif
