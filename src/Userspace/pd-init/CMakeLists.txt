add_darwin_executable(pd-init MACOSX_VERSION_MIN 26.5)

target_sources(pd-init PRIVATE
    entry.S
    syscalls.S
    main.c
)

target_compile_options(pd-init PRIVATE
    -ffreestanding
    -fno-builtin
    -fno-stack-protector
    -fno-exceptions
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
)

target_link_options(pd-init PRIVATE
    -nostdlib
    -Wl,-static
    -Wl,-e,_pd_start
)

install(TARGETS pd-init DESTINATION sbin COMPONENT BaseSystem)
