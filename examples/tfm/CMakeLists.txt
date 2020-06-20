include_directories(
   .
)

set(sv_9_2_LE_tfm_SRCS
   iec61850_9_2_LE_tfm.c
)
set(sv_config_SRCS
   ini.c
   sv_config.c
)

add_executable(sv_9_2_LE_tfm
  ${sv_9_2_LE_tfm_SRCS}
)
add_executable(sv_config
  ${sv_config_SRCS}
)

target_link_libraries(sv_9_2_LE_tfm
    iec61850
)
