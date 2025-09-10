#!/bin/bash

echo "$COMPOSER_HOME: $COMPOSER_HOME"

# Allow the plugin installer
composer global config --no-plugins allow-plugins.dealerdirect/phpcodesniffer-composer-installer true

# Install Drupal coding standards
composer global require drupal/coder

# Install PHP compatibility checker
composer global require phpcompatibility/php-compatibility

export PATH="$PATH:$COMPOSER_HOME/vendor/bin"

# Install PHPCS plugin installer
composer global require dealerdirect/phpcodesniffer-composer-installer

composer global show -P
$COMPOSER_HOME/vendor/bin/phpcs -i

# Configure PHPCS settings
$COMPOSER_HOME/vendor/bin/phpcs --config-set colors 1
$COMPOSER_HOME/vendor/bin/phpcs --config-set ignore_warnings_on_exit 1
$COMPOSER_HOME/vendor/bin/phpcs --config-set drupal_core_version 11

$COMPOSER_HOME/vendor/bin/phpcs --config-show