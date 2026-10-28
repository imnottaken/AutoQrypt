# PQClean (https://github.com/PQClean/PQClean @ 0586a824): ML-DSA-44 and Falcon-padded-512, "clean" C.
file(GLOB srcs "${CMAKE_CURRENT_LIST_DIR}/ml-dsa-44/*.c" "${CMAKE_CURRENT_LIST_DIR}/falcon-padded-512/*.c")
idf_component_register(
    SRCS ${srcs} "common/fips202.c" "randombytes_esp.c"
    INCLUDE_DIRS "." "common"
    PRIV_REQUIRES esp_hw_support)
