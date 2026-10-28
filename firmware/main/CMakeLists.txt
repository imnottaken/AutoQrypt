idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS "."
                       REQUIRES nvs_flash app_update esp_timer esp_hw_support esp_driver_uart esp_driver_gpio
                                esp_app_format heap pqclean monocypher)
target_compile_definitions(${COMPONENT_LIB} PRIVATE APP_FW_VERSION=${APP_FW_VERSION})
