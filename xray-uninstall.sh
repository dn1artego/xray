#!/bin/bash

# 1. Проверка на root-права
if [[ $(id -u) -ne 0 ]]; then
   echo "Этот скрипт нужно запускать с правами root (используйте sudo)."
   exit 1
fi

# 2. Остановка и отключение службы Xray
echo "Остановка и отключение службы Xray..."
systemctl stop xray
systemctl disable xray

# 3. Запуск официального скрипта удаления
echo "Запуск официального деинсталлятора Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove

# 4. Удаление вспомогательных скриптов
echo "Удаление вспомогательных утилит..."
rm -f /usr/local/bin/userlist
rm -f /usr/local/bin/mainuser
rm -f /usr/local/bin/newuser
rm -f /usr/local/bin/rmuser
rm -f /usr/local/bin/sharelink

# 5. Удаление файла с подсказками
# Пытаемся найти файл подсказок в домашней директории пользователя, который запустил скрипт с sudo
if [ -n "$SUDO_USER" ]; then
    HELP_FILE_PATH="/home/$SUDO_USER/xray_help.txt"
    if [ -f "$HELP_FILE_PATH" ]; then
        echo "Удаление файла с подсказками..."
        rm -f "$HELP_FILE_PATH"
    fi
else
    # Если SUDO_USER не определен, ищем в /root
    HELP_FILE_PATH="/root/xray_help.txt"
    if [ -f "$HELP_FILE_PATH" ]; then
        echo "Удаление файла с подсказками..."
        rm -f "$HELP_FILE_PATH"
    fi
fi


echo ""
echo "=========================================="
echo "Xray успешно удален из системы."
echo "=========================================="
