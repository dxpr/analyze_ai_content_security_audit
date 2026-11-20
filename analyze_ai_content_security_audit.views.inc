<?php

/**
 * @file
 */

use Drupal\Core\Hook\Attribute\LegacyHook;
use Drupal\analyze_ai_content_security_audit\Hook\AnalyzeAiContentSecurityAuditViewsHooks;

/**
 * @file
 * Provide views data for analyze_ai_content_security_audit.module.
 */

/**
 * Implements hook_views_data().
 */
#[LegacyHook]
function analyze_ai_content_security_audit_views_data() {
  return \Drupal::service(AnalyzeAiContentSecurityAuditViewsHooks::class)->viewsData();
}
