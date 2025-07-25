#!/bin/bash

echo "Запускаем обновление Xray-core..."
bash -c "$(curl -4 -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

echo "Обновляем файлы GeoIP и GeoSite..."
bash -c "$(curl -4 -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-dat-release

echo "Перезапускаем службу Xray..."
systemctl restart xray

echo "Обновление успешно завершено!"
