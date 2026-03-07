#!/bin/bash
# Скрипт для обновления приложения на сервере
# Использование: ./deploy.sh

set -e

echo "🚀 Начинаем деплой..."

# Остановка приложения
echo "⏸️  Остановка приложения..."
sudo systemctl stop browsermessage

# Обновление кода
echo "⬇️  Обновление кода из git..."
cd /var/www/browsermessage
git fetch origin
git reset --hard origin/main  # Или ветка, которую вы используете

# Обновление зависимостей
echo "📦 Установка зависимостей..."
npm install --production

# Запуск приложения
echo "▶️  Запуск приложения..."
sudo systemctl start browsermessage

# Проверка статуса
echo "✅ Проверка статуса..."
sudo systemctl status browsermessage

echo "🎉 Деплой завершён!"
