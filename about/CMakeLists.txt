



########### next target ###############

set(kio_about_PART_SRCS kio_about.cpp )


add_library(kio_about ${kio_about_PART_SRCS})


target_link_libraries(kio_about  KF5::KIOCore Qt5::Network)

install(TARGETS kio_about  DESTINATION ${PLUGIN_INSTALL_DIR} )


########### install files ###############

install( FILES about.protocol  DESTINATION  ${SERVICES_INSTALL_DIR} )
