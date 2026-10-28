idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS "."
                       REQUIRES nvs_flash app_update esp_timer esp_hw_support esp_driver_uart heap pqclean monocypher)
