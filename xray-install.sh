#!/bin/bash

# =================================================================
# Функции для создания вспомогательных скриптов
# =================================================================

create_userlist_script() {
    cat << 'EOF' > /usr/local/bin/userlist
#!/bin/bash
emails=($(jq -r '.inbounds[0].settings.clients[].email' "/usr/local/etc/xray/config.json"))

if [[ ${#emails[@]} -eq 0 ]]; then
    echo "Список клиентов пуст"
    exit 1
fi

echo "Список клиентов:"
for i in "${!emails[@]}"; do
    echo "$((i+1)). ${emails[$i]}"
done
EOF
    chmod +x /usr/local/bin/userlist
}

create_mainuser_script() {
    cat << 'EOF' > /usr/local/bin/mainuser
#!/bin/bash
protocol=$(jq -r '.inbounds[0].protocol' /usr/local/etc/xray/config.json)
port=$(jq -r '.inbounds[0].port' /usr/local/etc/xray/config.json)
uuid=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/uuid/ {print $2}')
pbk=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/Public key/ {print $2}')
sid=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/shortsid/ {print $2}')
sni=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' /usr/local/etc/xray/config.json)
ip=$(timeout 3 curl -4 -s icanhazip.com || echo "YOUR_SERVER_IP")
link="$protocol://$uuid@$ip:$port?security=reality&sni=$sni&fp=firefox&pbk=$pbk&sid=$sid&spx=/&type=tcp&flow=xtls-rprx-vision&encryption=none#vless-$ip"
echo ""
echo "Ссылка для подключения основного пользователя":
echo "$link"
echo ""
echo "QR-код:"
echo "${link}" | qrencode -t ansiutf8
EOF
    chmod +x /usr/local/bin/mainuser
}

create_newuser_script() {
    cat << 'EOF' > /usr/local/bin/newuser
#!/bin/bash
read -p "Введите имя пользователя (email): " email

if [[ -z "$email" || "$email" == *" "* ]]; then
    echo "Имя пользователя не может быть пустым или содержать пробелы. Попробуйте снова."
    exit 1
fi

user_json=$(jq --arg email "$email" '.inbounds[0].settings.clients[] | select(.email == $email)' /usr/local/etc/xray/config.json)

if [[ -z "$user_json" ]]; then
    uuid=$(xray uuid)
    jq --arg email "$email" --arg uuid "$uuid" '.inbounds[0].settings.clients += [{"email": $email, "id": $uuid, "flow": "xtls-rprx-vision"}]' /usr/local/etc/xray/config.json > tmp.json && mv tmp.json /usr/local/etc/xray/config.json
    systemctl restart xray
    
    index=$(jq --arg email "$email" '.inbounds[0].settings.clients | to_entries[] | select(.value.email == $email) | .key'  /usr/local/etc/xray/config.json)
    protocol=$(jq -r '.inbounds[0].protocol' /usr/local/etc/xray/config.json)
    port=$(jq -r '.inbounds[0].port' /usr/local/etc/xray/config.json)
    uuid=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].id' /usr/local/etc/xray/config.json)
    pbk=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/Public key/ {print $2}')
    sid=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/shortsid/ {print $2}')
    username=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].email' /usr/local/etc/xray/config.json)
    sni=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' /usr/local/etc/xray/config.json)
    ip=$(timeout 3 curl -4 -s icanhazip.com || echo "YOUR_SERVER_IP")
    link="$protocol://$uuid@$ip:$port?security=reality&sni=$sni&fp=firefox&pbk=$pbk&sid=$sid&spx=/&type=tcp&flow=xtls-rprx-vision&encryption=none#$username"
    
    echo ""
    echo "Пользователь $username успешно создан."
    echo "Ссылка для подключения":
    echo "$link"
    echo ""
    echo "QR-код:"
    echo "${link}" | qrencode -t ansiutf8
else
    echo "Пользователь с таким именем уже существует. Попробуйте снова." 
fi
EOF
    chmod +x /usr/local/bin/newuser
}

create_rmuser_script() {
    cat << 'EOF' > /usr/local/bin/rmuser
#!/bin/bash
emails=($(jq -r '.inbounds[0].settings.clients[].email' "/usr/local/etc/xray/config.json"))

if [[ ${#emails[@]} -eq 0 ]]; then
    echo "Нет клиентов для удаления."
    exit 1
fi

echo "Выберите клиента для удаления:"
for i in "${!emails[@]}"; do
    echo "$((i+1)). ${emails[$i]}"
done

read -p "Введите номер клиента: " choice

if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#emails[@]} )); then
    echo "Ошибка: номер должен быть от 1 до ${#emails[@]}"
    exit 1
fi

selected_email="${emails[$((choice - 1))]}"

if [[ "$selected_email" == "main" ]]; then
    echo "Ошибка: основного пользователя 'main' удалять нельзя."
    exit 1
fi

jq --arg email "$selected_email" \
   '(.inbounds[0].settings.clients) |= map(select(.email != $email))' \
   "/usr/local/etc/xray/config.json" > tmp && mv tmp "/usr/local/etc/xray/config.json"

systemctl restart xray

echo "Клиент $selected_email удалён."
EOF
    chmod +x /usr/local/bin/rmuser
}

create_sharelink_script() {
    cat << 'EOF' > /usr/local/bin/sharelink
#!/bin/bash
emails=($(jq -r '.inbounds[0].settings.clients[].email' /usr/local/etc/xray/config.json))

echo "Выберите клиента для генерации ссылки:"
for i in "${!emails[@]}"; do
   echo "$((i + 1)). ${emails[$i]}"
done

read -p "Введите номер клиента: " client_choice

if ! [[ "$client_choice" =~ ^[0-9]+$ ]] || (( client_choice < 1 || client_choice > ${#emails[@]} )); then
    echo "Ошибка: номер должен быть от 1 до ${#emails[@]}"
    exit 1
fi

selected_email="${emails[$((client_choice - 1))]}"


index=$(jq --arg email "$selected_email" '.inbounds[0].settings.clients | to_entries[] | select(.value.email == $email) | .key'  /usr/local/etc/xray/config.json)
protocol=$(jq -r '.inbounds[0].protocol' /usr/local/etc/xray/config.json)
port=$(jq -r '.inbounds[0].port' /usr/local/etc/xray/config.json) 
uuid=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].id' /usr/local/etc/xray/config.json)
pbk=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/Public key/ {print $2}')
sid=$(cat /usr/local/etc/xray/.keys | awk -F': ' '/shortsid/ {print $2}')
username=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].email' /usr/local/etc/xray/config.json)
sni=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' /usr/local/etc/xray/config.json)
ip=$(timeout 3 curl -4 -s icanhazip.com || echo "YOUR_SERVER_IP")
link="$protocol://$uuid@$ip:$port?security=reality&sni=$sni&fp=firefox&pbk=$pbk&sid=$sid&spx=/&type=tcp&flow=xtls-rprx-vision&encryption=none#$username"
echo ""
echo "Ссылка для подключения ($username)":
echo "$link"
echo ""
echo "QR-код:"
echo "${link}" | qrencode -t ansiutf8
EOF
    chmod +x /usr/local/bin/sharelink
}

create_help_file() {
    cat << EOF > "$1"

Команды для управления пользователями Xray:

    mainuser    - выводит ссылку для подключения основного пользователя
    newuser     - создает нового пользователя
    rmuser      - удаление пользователей
    sharelink   - выводит список пользователей и позволяет создать для них ссылки
    userlist    - выводит список клиентов

Файл конфигурации находится по адресу:
    /usr/local/etc/xray/config.json

Команда для перезагрузки ядра Xray:
    systemctl restart xray

EOF
}

# =================================================================
# Основной скрипт
# =================================================================

# 1. Проверка на root-права
if [[ $(id -u) -ne 0 ]]; then
   echo "Этот скрипт нужно запускать с правами root (используйте sudo)."
   exit 1
fi

# 2. Установка зависимостей
echo "Обновление списка пакетов и установка зависимостей..."
apt update
apt install qrencode curl jq -y

# 3. Включение BBR
echo "Проверка и включение BBR..."
if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi
    sysctl -p
    echo "BBR включен."
else
    echo "BBR уже включен."
fi

# 4. Установка ядра Xray
echo "Установка Xray-core..."
bash -c "$(curl -4 -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 5. Генерация ключей и ID
echo "Генерация ключей и идентификаторов..."
[ -f /usr/local/etc/xray/.keys ] && rm /usr/local/etc/xray/.keys
touch /usr/local/etc/xray/.keys
echo "uuid: $(xray uuid)" >> /usr/local/etc/xray/.keys
xray x25519 >> /usr/local/etc/xray/.keys
echo "shortsid: $(openssl rand -hex 8)" >> /usr/local/etc/xray/.keys

# Считываем ключи в переменные
uuid=$(awk -F': ' '/uuid/ {print $2}' /usr/local/etc/xray/.keys)
privatekey=$(awk -F': ' '/Private key/ {print $2}' /usr/local/etc/xray/.keys)
shortsid=$(awk -F': ' '/shortsid/ {print $2}' /usr/local/etc/xray/.keys)

# 6. Запрос данных для конфигурации
read -p "Введите домен для маскировки (нажмите Enter для github.com): " reality_dest
reality_dest=${reality_dest:-"github.com"}
echo "Будет использован домен: $reality_dest"

# 7. Создание файла конфигурации Xray
echo "Создание файла конфигурации..."
touch /usr/local/etc/xray/config.json
cat << EOF > /usr/local/etc/xray/config.json
{
    "log": {
        "loglevel": "warning"
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "domain": [
                    "geosite:category-ads-all"
                ],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "ip": [
                    "geoip:cn",
                    "geoip:ru",
                    "geoip:ir"
                ],
                "outboundTag": "block"
            }
        ]
    },
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "email": "main",
                        "id": "$uuid",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "$reality_dest:443",
                    "xver": 0,
                    "serverNames": [
                        "$reality_dest",
                        "www.$reality_dest"
                    ],
                    "privateKey": "$privatekey",
                    "minClientVer": "",
                    "maxClientVer": "",
                    "maxTimeDiff": 0,
                    "shortIds": [
                        "$shortsid"
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ],
    "policy": {
        "levels": {
            "0": {
                "handshake": 3,
                "connIdle": 180
            }
        }
    }
}
EOF

# 8. Создание вспомогательных скриптов
echo "Создание утилит для управления..."
create_userlist_script
create_mainuser_script
create_newuser_script
create_rmuser_script
create_sharelink_script

# 9. Перезапуск Xray
systemctl restart xray

# 10. Завершение
echo ""
echo "=================================================="
echo "Xray-core успешно установлен и настроен!"
echo "=================================================="
echo ""

mainuser

# Создаем файл с подсказками
HELP_FILE_PATH="$HOME/xray_help.txt"
create_help_file "$HELP_FILE_PATH"

echo ""
echo "Файл с подсказками создан: $HELP_FILE_PATH"
echo "Для просмотра подсказок введите: cat $HELP_FILE_PATH"
