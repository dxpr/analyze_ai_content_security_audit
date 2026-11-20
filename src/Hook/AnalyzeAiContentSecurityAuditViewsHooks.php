<?php

namespace Drupal\analyze_ai_content_security_audit\Hook;

use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\StringTranslation\StringTranslationTrait;

/**
 * Hook implementations for analyze_ai_content_security_audit.
 */
class AnalyzeAiContentSecurityAuditViewsHooks {
  use StringTranslationTrait;
  /**
   * @file
   * Provide views data for analyze_ai_content_security_audit.module.
   */

  /**
   * Implements hook_views_data().
   */
  #[Hook('views_data')]
  public function viewsData() {
    $data = [];
    $data['analyze_ai_content_security_audit_results']['table']['group'] = $this->t('Content Security Audit');
    $data['analyze_ai_content_security_audit_results']['table']['base'] = [
      'field' => 'id',
      'title' => $this->t('Content Security Audit Results'),
      'help' => $this->t('AI content security risk analysis scores for content entities.'),
    ];
    // ID field.
    $data['analyze_ai_content_security_audit_results']['id'] = [
      'title' => $this->t('Analysis ID'),
      'help' => $this->t('The unique ID of the analysis result.'),
      'field' => [
        'id' => 'numeric',
      ],
      'filter' => [
        'id' => 'numeric',
      ],
      'sort' => [
        'id' => 'standard',
      ],
      'argument' => [
        'id' => 'numeric',
      ],
    ];
    // Entity type field.
    $data['analyze_ai_content_security_audit_results']['entity_type'] = [
      'title' => $this->t('Entity Type'),
      'help' => $this->t('The type of entity that was analyzed.'),
      'field' => [
        'id' => 'standard',
      ],
      'filter' => [
        'id' => 'string',
      ],
      'sort' => [
        'id' => 'standard',
      ],
      'argument' => [
        'id' => 'string',
      ],
    ];
    // Entity ID field with relationship to content.
    $data['analyze_ai_content_security_audit_results']['entity_id'] = [
      'title' => $this->t('Entity ID'),
      'help' => $this->t('The ID of the entity that was analyzed.'),
      'field' => [
        'id' => 'numeric',
      ],
      'filter' => [
        'id' => 'numeric',
      ],
      'sort' => [
        'id' => 'standard',
      ],
      'argument' => [
        'id' => 'numeric',
      ],
      'relationship' => [
        'id' => 'standard',
        'base' => 'node_field_data',
        'base field' => 'nid',
        'field' => 'entity_id',
        'label' => $this->t('Content'),
        'title' => $this->t('Content'),
        'help' => $this->t('The content entity that was analyzed.'),
      ],
    ];
    // Entity revision ID field.
    $data['analyze_ai_content_security_audit_results']['entity_revision_id'] = [
      'title' => $this->t('Entity Revision ID'),
      'help' => $this->t('The revision ID of the entity that was analyzed.'),
      'field' => [
        'id' => 'numeric',
      ],
      'filter' => [
        'id' => 'numeric',
      ],
      'sort' => [
        'id' => 'standard',
      ],
      'argument' => [
        'id' => 'numeric',
      ],
    ];
    // Language code field.
    $data['analyze_ai_content_security_audit_results']['langcode'] = [
      'title' => $this->t('Language'),
      'help' => $this->t('The language of the analyzed content.'),
      'field' => [
        'id' => 'language',
      ],
      'filter' => [
        'id' => 'language',
      ],
      'sort' => [
        'id' => 'standard',
      ],
      'argument' => [
        'id' => 'language',
      ],
    ];
    // Vector ID field.
    $data['analyze_ai_content_security_audit_results']['vector_id'] = [
      'title' => $this->t('Security Vector'),
      'help' => $this->t('The security vector identifier (e.g., "pii_disclosure", "credentials_disclosure").'),
      'field' => [
        'id' => 'standard',
      ],
      'filter' => [
        'id' => 'analyze_select',
        'options_callback' => 'analyze_ai_content_security_audit.storage:getVectorOptions',
      ],
      'sort' => [
        'id' => 'standard',
      ],
      'argument' => [
        'id' => 'string',
      ],
    ];
    // Security risk score field.
    $data['analyze_ai_content_security_audit_results']['score'] = [
      'title' => $this->t('Security Risk Score'),
      'help' => $this->t('The security risk score (0 to 100).'),
      'field' => [
        'id' => 'numeric',
        'float' => FALSE,
      ],
      'filter' => [
        'id' => 'numeric',
      ],
      'sort' => [
        'id' => 'standard',
      ],
      'argument' => [
        'id' => 'numeric',
      ],
    ];
    // Content hash field.
    $data['analyze_ai_content_security_audit_results']['content_hash'] = [
      'title' => $this->t('Content Hash'),
      'help' => $this->t('The SHA256 hash of the analyzed content.'),
      'field' => [
        'id' => 'standard',
      ],
      'filter' => [
        'id' => 'string',
      ],
      'sort' => [
        'id' => 'standard',
      ],
      'argument' => [
        'id' => 'string',
      ],
    ];
    // Config hash field.
    $data['analyze_ai_content_security_audit_results']['config_hash'] = [
      'title' => $this->t('Config Hash'),
      'help' => $this->t('The MD5 hash of the security vector configuration.'),
      'field' => [
        'id' => 'standard',
      ],
      'filter' => [
        'id' => 'string',
      ],
      'sort' => [
        'id' => 'standard',
      ],
      'argument' => [
        'id' => 'string',
      ],
    ];
    // Analysis timestamp field.
    $data['analyze_ai_content_security_audit_results']['analyzed_timestamp'] = [
      'title' => $this->t('Analysis Date'),
      'help' => $this->t('The date and time when the analysis was performed.'),
      'field' => [
        'id' => 'date',
        'click sortable' => TRUE,
      ],
      'filter' => [
        'id' => 'date',
      ],
      'sort' => [
        'id' => 'date',
      ],
      'argument' => [
        'id' => 'date',
      ],
    ];
    return $data;
  }

}
