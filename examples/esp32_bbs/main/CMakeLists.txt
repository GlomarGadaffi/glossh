idf_component_register(SRCS "main.c" "bbs.c" "bbs_art.c" "bbs_plat_esp.c"
                       PRIV_REQUIRES littlessh glotui nvs_flash esp_eth esp_netif
                                     esp_event esp_driver_spi esp_driver_gpio
                                     esp_hw_support esp_timer spi_flash)
