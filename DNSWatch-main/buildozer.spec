[app]
title = DNS Sniffer
domain = org.yourdomain
description = A powerful DNS sniffer with dynamic UI and enhanced features.
package.name = dns_sniffer
package.domain = org.yourdomain
source.include_exts = py,png,jpg,kv,ttf
version = 1.0
debug = 0

# Full application entry point
source.dir = .
main.py = main.py

# Requirements
requirements = python3,kivy,requests,scapy,pillow

# Android Specifics
android.permissions = INTERNET,ACCESS_NETWORK_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE
android.api = 31
android.minapi = 21
android.ndk = 23b
android.gradle_dependencies = 'com.google.android.material:material:1.4.0'
android.meta_data = android.permission.FOREGROUND_SERVICE
android.screens = small, normal, large, xlarge
android.preserve_python_bytecode = True

# Features for better performance
default.orientation = portrait
fullscreen = 1
android.entrypoint = org.kivy.android.PythonActivity

# Icons and Assets
icon.filename = ./assets/icon.png
presplash.filename = ./assets/presplash.png

# Build Settings
default.language = en
distutils_setuptools = 1
android.allow_cleartext_access = True

# Packaging
package.mode = release

# Extra Files and Directories
android.add_src = ./src
android.add_assets = ./assets

# Sign the APK
p4a.branch = master
android.arch = arm64-v8a, armeabi-v7a, x86_64

# Optimize APK Size
android.no-compile-pyo = True

# Additional libraries
p4a.local_recipes = ./custom_recipes
android.add_activity = com.example.dns_sniffer.DnsActivity

# Log Configuration
debug_symbols = 1
log_level = 2

# Exclude files
exclude_patterns = .git*, __pycache__, *.pyc, *.pyo
