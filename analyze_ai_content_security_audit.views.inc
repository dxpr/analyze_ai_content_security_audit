<?php

/**
 * @file
 * Provide views data for analyze_ai_content_security_audit.module.
 */

/**
 * Implements hook_views_data().
 */
function analyze_ai_content_security_audit_views_data() {
  $data = [];

  $data['analyze_ai_content_security_audit_results']['table']['group'] = t('Content Security Audit');
  $data['analyze_ai_content_security_audit_results']['table']['base'] = [
    'field' => 'id',
    'title' => t('Content Security Audit Results'),
    'help' => t('AI content security risk analysis scores for content entities.'),
  ];

  // ID field.
  $data['analyze_ai_content_security_audit_results']['id'] = [
    'title' => t('Analysis ID'),
    'help' => t('The unique ID of the analysis result.'),
    'field' => ['id' => 'numeric'],
    'filter' => ['id' => 'numeric'],
    'sort' => ['id' => 'standard'],
    'argument' => ['id' => 'numeric'],
  ];

  // Entity type field.
  $data['analyze_ai_content_security_audit_results']['entity_type'] = [
    'title' => t('Entity Type'),
    'help' => t('The type of entity that was analyzed.'),
    'field' => ['id' => 'standard'],
    'filter' => ['id' => 'string'],
    'sort' => ['id' => 'standard'],
    'argument' => ['id' => 'string'],
  ];

  // Entity ID field with relationship to content.
  $data['analyze_ai_content_security_audit_results']['entity_id'] = [
    'title' => t('Entity ID'),
    'help' => t('The ID of the entity that was analyzed.'),
    'field' => ['id' => 'numeric'],
    'filter' => ['id' => 'numeric'],
    'sort' => ['id' => 'standard'],
    'argument' => ['id' => 'numeric'],
    'relationship' => [
      'id' => 'standard',
      'base' => 'node_field_data',
      'base field' => 'nid',
      'field' => 'entity_id',
      'label' => t('Content'),
      'title' => t('Content'),
      'help' => t('The content entity that was analyzed.'),
    ],
  ];

  // Entity revision ID field.
  $data['analyze_ai_content_security_audit_results']['entity_revision_id'] = [
    'title' => t('Entity Revision ID'),
    'help' => t('The revision ID of the entity that was analyzed.'),
    'field' => ['id' => 'numeric'],
    'filter' => ['id' => 'numeric'],
    'sort' => ['id' => 'standard'],
    'argument' => ['id' => 'numeric'],
  ];

  // Language code field.
  $data['analyze_ai_content_security_audit_results']['langcode'] = [
    'title' => t('Language'),
    'help' => t('The language of the analyzed content.'),
    'field' => ['id' => 'standard'],
    'filter' => ['id' => 'string'],
    'sort' => ['id' => 'standard'],
    'argument' => ['id' => 'string'],
  ];

  // Vector ID field.
  $data['analyze_ai_content_security_audit_results']['vector_id'] = [
    'title' => t('Security Vector'),
    'help' => t('The security vector identifier (e.g., "pii_disclosure", "credentials_disclosure").'),
    'field' => ['id' => 'standard'],
    'filter' => ['id' => 'string'],
    'sort' => ['id' => 'standard'],
    'argument' => ['id' => 'string'],
  ];

  // Security risk score field.
  $data['analyze_ai_content_security_audit_results']['score'] = [
    'title' => t('Security Risk Score'),
    'help' => t('The security risk score (0 to 100).'),
    'field' => [
      'id' => 'numeric',
      'float' => FALSE,
    ],
    'filter' => [
      'id' => 'numeric',
    ],
    'sort' => ['id' => 'standard'],
    'argument' => ['id' => 'numeric'],
  ];

  // Content hash field.
  $data['analyze_ai_content_security_audit_results']['content_hash'] = [
    'title' => t('Content Hash'),
    'help' => t('The SHA256 hash of the analyzed content.'),
    'field' => ['id' => 'standard'],
    'filter' => ['id' => 'string'],
    'sort' => ['id' => 'standard'],
    'argument' => ['id' => 'string'],
  ];

  // Config hash field.
  $data['analyze_ai_content_security_audit_results']['config_hash'] = [
    'title' => t('Config Hash'),
    'help' => t('The MD5 hash of the security vector configuration.'),
    'field' => ['id' => 'standard'],
    'filter' => ['id' => 'string'],
    'sort' => ['id' => 'standard'],
    'argument' => ['id' => 'string'],
  ];

  // Analysis timestamp field.
  $data['analyze_ai_content_security_audit_results']['analyzed_timestamp'] = [
    'title' => t('Analysis Date'),
    'help' => t('The date and time when the analysis was performed.'),
    'field' => [
      'id' => 'date',
      'click sortable' => TRUE,
    ],
    'filter' => ['id' => 'date'],
    'sort' => ['id' => 'date'],
    'argument' => ['id' => 'date'],
  ];

  return $data;
}