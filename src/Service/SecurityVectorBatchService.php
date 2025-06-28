<?php

declare(strict_types=1);

namespace Drupal\analyze_ai_content_security_audit\Service;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\DependencyInjection\DependencySerializationTrait;
use Drupal\analyze_ai_content_security_audit\Service\SecurityVectorStorageService;

/**
 * Service for batch processing security vector analysis.
 */
final class SecurityVectorBatchService {

  use StringTranslationTrait;
  use DependencySerializationTrait;

  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly SecurityVectorStorageService $storage,
  ) {}

  /**
   * Gets entities that need security analysis.
   *
   * @param array $entity_bundles
   *   Array of entity_type:bundle strings.
   * @param bool $force_refresh
   *   Whether to include entities with existing analysis.
   * @param int $limit
   *   Maximum number of entities to return.
   *
   * @return array
   *   Array of entity info arrays.
   */
  public function getEntitiesForAnalysis(array $entity_bundles, bool $force_refresh = FALSE, int $limit = 0): array {
    $entities = [];
    
    foreach ($entity_bundles as $entity_bundle) {
      [$entity_type_id, $bundle] = explode(':', $entity_bundle);
      
      $query = $this->entityTypeManager->getStorage($entity_type_id)
        ->getQuery()
        ->accessCheck(TRUE)
        ->condition('type', $bundle);
      
      // Only include published content.
      if ($entity_type_id === 'node') {
        $query->condition('status', 1);
      }

      if (!$force_refresh) {
        // Only include entities that need analysis (no valid cache).
        $analyzed_ids = $this->getAnalyzedEntityIds($entity_type_id, $bundle);
        if (!empty($analyzed_ids)) {
          $query->condition($entity_type_id === 'node' ? 'nid' : 'id', $analyzed_ids, 'NOT IN');
        }
      }
      
      if ($limit > 0) {
        $remaining = $limit - count($entities);
        if ($remaining <= 0) {
          break;
        }
        $query->range(0, $remaining);
      }
      
      $ids = $query->execute();
      
      foreach ($ids as $id) {
        $entities[] = [
          'entity_type' => $entity_type_id,
          'entity_id' => $id,
          'bundle' => $bundle,
        ];
      }
    }

    return $entities;
  }

  /**
   * Processes a batch of entities for security analysis.
   *
   * @param array $entities
   *   Array of entity info.
   * @param bool $force_refresh
   *   Whether to force fresh analysis.
   * @param array $context
   *   Batch context.
   */
  public function processBatch(array $entities, bool $force_refresh, array &$context): void {
    if (!isset($context['sandbox']['progress'])) {
      $context['sandbox']['progress'] = 0;
      $context['sandbox']['max'] = count($entities);
      $context['results']['processed'] = 0;
      $context['results']['errors'] = [];
    }

    try {
      $analyzer = \Drupal::service('plugin.manager.analyze')
        ->createInstance('content_security_audit_analyzer');

      foreach ($entities as $entity_data) {
        try {
          $entity = $this->entityTypeManager
            ->getStorage($entity_data['entity_type'])
            ->load($entity_data['entity_id']);

          if ($entity) {
            if ($force_refresh) {
              $this->storage->deleteScores($entity);
            }
            
            // Capture any output to prevent JSON corruption.
            ob_start();
            $analyzer->renderSummary($entity);
            ob_end_clean();
            
            $context['results']['processed']++;
          }
        } catch (\Exception $e) {
          $context['results']['errors'][] = $this->t('Error processing @type @id: @message', [
            '@type' => $entity_data['entity_type'],
            '@id' => $entity_data['entity_id'],
            '@message' => $e->getMessage(),
          ])->render();
        }

        $context['sandbox']['progress']++;
      }
    } catch (\Exception $e) {
      $context['results']['errors'][] = $this->t('Batch processing error: @message', [
        '@message' => $e->getMessage(),
      ])->render();
    }

    $context['message'] = $this->t('Processing @current of @max entities...', [
      '@current' => $context['sandbox']['progress'],
      '@max' => $context['sandbox']['max'],
    ])->render();

    $context['finished'] = $context['sandbox']['progress'] / $context['sandbox']['max'];
  }

  /**
   * Gets IDs of entities that already have recent analysis.
   *
   * @param string $entity_type_id
   *   The entity type ID.
   * @param string $bundle
   *   The bundle.
   *
   * @return array
   *   Array of entity IDs that have been analyzed recently.
   */
  private function getAnalyzedEntityIds(string $entity_type_id, string $bundle): array {
    $database = \Drupal::database();
    
    // Get entities analyzed in the last 7 days with current config.
    $current_config_hash = $this->storage->generateConfigHash();
    $week_ago = time() - (7 * 24 * 60 * 60);
    
    $query = $database->select('analyze_ai_content_security_audit_results', 'r')
      ->fields('r', ['entity_id'])
      ->condition('entity_type', $entity_type_id)
      ->condition('config_hash', $current_config_hash)
      ->condition('analyzed_timestamp', $week_ago, '>')
      ->distinct();
    
    return $query->execute()->fetchCol();
  }

  /**
   * Gets the available entity bundles that have security analysis enabled.
   *
   * @return array
   *   Array of entity_type:bundle => label pairs.
   */
  public function getAvailableEntityBundles(): array {
    $config = \Drupal::config('analyze.settings');
    $status = $config->get('status') ?? [];
    
    $options = [];
    foreach ($status as $entity_type_id => $bundles) {
      foreach ($bundles as $bundle => $analyzers) {
        if (isset($analyzers['content_security_audit_analyzer'])) {
          // Get human-readable names.
          $entity_type = $this->entityTypeManager->getDefinition($entity_type_id);
          $bundle_info = \Drupal::service('entity_type.bundle.info')->getBundleInfo($entity_type_id);
          
          $entity_label = $entity_type->getLabel();
          $bundle_label = $bundle_info[$bundle]['label'] ?? $bundle;
          
          $options["{$entity_type_id}:{$bundle}"] = "{$entity_label} - {$bundle_label}";
        }
      }
    }

    return $options;
  }

}