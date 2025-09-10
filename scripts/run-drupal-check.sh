#!/bin/bash
set -vo pipefail

DRUPAL_RECOMMENDED_PROJECT=${DRUPAL_RECOMMENDED_PROJECT:-11.x-dev}
PHP_EXTENSIONS="gd"
DRUPAL_CHECK_TOOL="mglaman/drupal-check:^2.0"

# Install required PHP extensions (skip in local environment)
# for ext in $PHP_EXTENSIONS; do
#   if ! php -m | grep -q $ext; then
#     apk update && apk add --no-cache ${ext}-dev
#     docker-php-ext-install $ext
#   fi
# done

# Create Drupal project if it doesn't exist
if [ ! -d "drupal" ]; then
  composer create-project drupal/recommended-project=$DRUPAL_RECOMMENDED_PROJECT drupal --no-interaction --stability=dev
fi

cd drupal

# Install the statistic modules if D11 (removed from core).
if [[ $DRUPAL_RECOMMENDED_PROJECT == 11.* ]]; then
  composer require drupal/statistics
fi

# Install drupal-check with compatible version
composer require $DRUPAL_CHECK_TOOL --dev --ignore-platform-reqs --with-all-dependencies || true

# Run drupal-check on src directory
./vendor/bin/drupal-check --drupal-root . -ad ../src/ 