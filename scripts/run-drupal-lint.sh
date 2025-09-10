#!/bin/bash

source scripts/prepare-drupal-lint.sh

EXIT_CODE=0

# Check PHP Compatibility for PHP 8.3+
echo "Checking PHP Compatibility (PHP 8.3+)..."
$COMPOSER_HOME/vendor/bin/phpcs --standard=PHPCompatibility \
  --runtime-set testVersion 8.3- \
  --extensions=php,module,inc,install,test,profile,theme \
  --ignore="node_modules,vendor,.github,var,drupal" \
  -v \
  .

status=$?
if [ $status -ne 0 ]; then
  EXIT_CODE=$status
fi

# Check Drupal coding standards
echo "Checking Drupal coding standards..."
$COMPOSER_HOME/vendor/bin/phpcs --standard=Drupal \
  --extensions=php,module,inc,install,test,profile,theme,info,txt,md,yml \
  --ignore="node_modules,vendor,.github,var,drupal" \
  -v \
  .

status=$?
if [ $status -ne 0 ]; then
  EXIT_CODE=$status
fi

# Check Drupal best practices
echo "Checking Drupal best practices..."
$COMPOSER_HOME/vendor/bin/phpcs --standard=DrupalPractice \
  --extensions=php,module,inc,install,test,profile,theme,info,txt,md,yml \
  --ignore="node_modules,vendor,.github,var,drupal" \
  -v \
  .

status=$?
if [ $status -ne 0 ]; then
  EXIT_CODE=$status
fi

exit $EXIT_CODE