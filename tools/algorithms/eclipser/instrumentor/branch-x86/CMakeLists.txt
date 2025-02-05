find_program(MAKE_EXE NAMES gmake nmake make)
set( QEMU_VERSION )
set( ECLIPSER_QEMU_VERSION "2.10.0" )
if( ${CMAKE_VERSION} VERSION_LESS 3.14.0 )
ExternalProject_Add(
  qemu-trace-branch-x86
  DOWNLOAD_COMMAND ""
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/../branch-x86_64/qemu-trace-branch-x86_64-prefix/src/qemu-trace-branch-x86_64/
  CONFIGURE_COMMAND
    "<SOURCE_DIR>/configure"
    "--prefix=<INSTALL_DIR>"
    "--disable-system"
    "--enable-linux-user"
    "--disable-gtk"
    "--disable-sdl"
    "--disable-vnc"
    "--python=python2.7"
    "--target-list=i386-linux-user"
  BUILD_COMMAND "${MAKE_EXE}"
  INSTALL_COMMAND "${MAKE_EXE}" "install"
  LOG_CONFIGURE TRUE
  LOG_BUILD TRUE
  LOG_INSTALL TRUE
  DEPENDS qemu-trace-branch-x86_64
)
else()
ExternalProject_Add(
  qemu-trace-branch-x86
  DOWNLOAD_COMMAND ""
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/../branch-x86_64/qemu-trace-branch-x86_64-prefix/src/qemu-trace-branch-x86_64/
  CONFIGURE_COMMAND
    "<SOURCE_DIR>/configure"
    "--prefix=<INSTALL_DIR>"
    "--disable-system"
    "--enable-linux-user"
    "--disable-gtk"
    "--disable-sdl"
    "--disable-vnc"
    "--python=python2.7"
    "--target-list=i386-linux-user"
  BUILD_COMMAND "${MAKE_EXE}"
  INSTALL_COMMAND "${MAKE_EXE}" "install"
  LOG_PATCH TRUE
  LOG_CONFIGURE TRUE
  LOG_BUILD TRUE
  LOG_INSTALL TRUE
  LOG_OUTPUT_ON_FAILURE TRUE
  DEPENDS qemu-trace-branch-x86_64
)
endif()

add_custom_target(
  tool-algorithms-eclipser-copy-qemu-trace-branch-x86
  ALL
  COMMAND ${CMAKE_COMMAND} -E
  copy ${CMAKE_CURRENT_BINARY_DIR}/qemu-trace-branch-x86-prefix/bin/qemu-i386 ${CMAKE_BINARY_DIR}/qemu-trace-branch-x86
  DEPENDS qemu-trace-branch-x86
)

install( PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/qemu-trace-branch-x86-prefix/bin/qemu-i386 DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME qemu-trace-branch-x86 )

