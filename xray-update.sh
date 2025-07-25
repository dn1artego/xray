#!/bin/bash

# 1. Проверка на root-права
if [[ $(id -u) -ne 0 ]]; then
   echo "Этот скрипт нужно запускать с правами root (используйте sudo)."
   exit 1
fi

echo "Запускаем обновление Xray-core..."
bash -c "$(curl -4 -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

echo "Обновляем файлы GeoIP и GeoSite..."
bash -c "$(curl -4 -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-dat-release

echo "Перезапускаем службу Xray..."
systemctl restart xray

echo "Обновление успешно завершено!"
