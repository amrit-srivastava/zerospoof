#!/bin/bash

# Azure App Service startup script for Django
# This script is executed when the app starts

# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate --noinput

# Collect static files
python manage.py collectstatic --noinput

# Start Gunicorn server
gunicorn --bind=0.0.0.0:8000 --workers=4 --threads=2 zerospoof.wsgi:application
