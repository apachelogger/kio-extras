set (KDED_FILENAMESEARCH_SRCS
     filenamesearchmodule.cpp
)

add_library(filenamesearchmodule MODULE ${KDED_FILENAMESEARCH_SRCS})
kcoreaddons_desktop_to_json(filenamesearchmodule filenamesearchmodule.desktop)

target_link_libraries(filenamesearchmodule
    KF5::DBusAddons
    KF5::KIOCore
)

install(TARGETS filenamesearchmodule DESTINATION ${PLUGIN_INSTALL_DIR}/kf5/kded)
