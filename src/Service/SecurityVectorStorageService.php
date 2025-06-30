<?php

declare(strict_types=1);

namespace Drupal\analyze_ai_content_security_audit\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\DependencyInjection\DependencySerializationTrait;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\RevisionableInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Render\RendererInterface;

/**
 * Service for storing and retrieving security vector analysis results.
 */
final class SecurityVectorStorageService {

  use DependencySerializationTrait;

  public function __construct(
    private readonly Connection $database,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly RendererInterface $renderer,
    private readonly LanguageManagerInterface $languageManager,
  ) {}

  /**
   * Gets the cached security scores for an entity.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity to get the scores for.
   *
   * @return array
   *   Array of vector_id => score pairs.
   */
  public function getScores(EntityInterface $entity): array {
    $content_hash = $this->generateContentHash($entity);
    $config_hash = $this->generateConfigHash();

    $results = $this->database->select('analyze_ai_content_security_audit_results', 'r')
      ->fields('r', ['vector_id', 'score'])
      ->condition('entity_type', $entity->getEntityTypeId())
      ->condition('entity_id', $entity->id())
      ->condition('langcode', $entity->language()->getId())
      ->condition('content_hash', $content_hash)
      ->condition('config_hash', $config_hash)
      ->execute()
      ->fetchAllKeyed();

    return array_map('intval', $results);
  }

  /**
   * Saves security scores for an entity.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity the scores are for.
   * @param array $scores
   *   Array of vector_id => score pairs.
   */
  public function saveScores(EntityInterface $entity, array $scores): void {
    $content_hash = $this->generateContentHash($entity);
    $config_hash = $this->generateConfigHash();

    // Delete existing scores for this entity/language combination.
    $this->database->delete('analyze_ai_content_security_audit_results')
      ->condition('entity_type', $entity->getEntityTypeId())
      ->condition('entity_id', $entity->id())
      ->condition('langcode', $entity->language()->getId())
      ->execute();

    // Insert new scores.
    if (!empty($scores)) {
      $insert = $this->database->insert('analyze_ai_content_security_audit_results')
        ->fields([
          'entity_type', 'entity_id', 'entity_revision_id', 'langcode',
          'vector_id', 'score', 'content_hash', 'config_hash', 'analyzed_timestamp',
        ]);

      foreach ($scores as $vector_id => $score) {
        // Ensure score is within valid range (0-100).
        $score = max(0, min(100, (int) $score));

        $insert->values([
          'entity_type' => $entity->getEntityTypeId(),
          'entity_id' => $entity->id(),
          'entity_revision_id' => $entity instanceof RevisionableInterface ? $entity->getRevisionId() : NULL,
          'langcode' => $entity->language()->getId(),
          'vector_id' => $vector_id,
          'score' => $score,
          'content_hash' => $content_hash,
          'config_hash' => $config_hash,
          'analyzed_timestamp' => \Drupal::time()->getRequestTime(),
        ]);
      }

      $insert->execute();
    }
  }

  /**
   * Deletes all stored scores for an entity.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity to delete scores for.
   */
  public function deleteScores(EntityInterface $entity): void {
    $this->database->delete('analyze_ai_content_security_audit_results')
      ->condition('entity_type', $entity->getEntityTypeId())
      ->condition('entity_id', $entity->id())
      ->execute();
  }

  /**
   * Invalidates all cached results due to configuration changes.
   */
  public function invalidateConfigCache(): void {
    // Delete all records with old config hash.
    $current_hash = $this->generateConfigHash();
    $this->database->delete('analyze_ai_content_security_audit_results')
      ->condition('config_hash', $current_hash, '!=')
      ->execute();
  }

  /**
   * Gets statistics about stored analysis results.
   *
   * @return array
   *   Array with count statistics.
   */
  public function getStatistics(): array {
    $query = $this->database->select('analyze_ai_content_security_audit_results', 'r');
    $query->addExpression('COUNT(*)', 'total_results');
    $query->addExpression('COUNT(DISTINCT entity_id)', 'unique_entities');
    $query->addExpression('COUNT(DISTINCT vector_id)', 'unique_vectors');
    $query->addExpression('MIN(analyzed_timestamp)', 'oldest_analysis');
    $query->addExpression('MAX(analyzed_timestamp)', 'newest_analysis');

    $result = $query->execute()->fetchAssoc();

    return [
      'total_results' => (int) $result['total_results'],
      'unique_entities' => (int) $result['unique_entities'],
      'unique_vectors' => (int) $result['unique_vectors'],
      'oldest_analysis' => $result['oldest_analysis'] ? (int) $result['oldest_analysis'] : 0,
      'newest_analysis' => $result['newest_analysis'] ? (int) $result['newest_analysis'] : 0,
    ];
  }

  /**
   * Gets average scores by vector type.
   *
   * @return array
   *   Array of vector_id => average_score pairs.
   */
  public function getAverageScores(): array {
    $query = $this->database->select('analyze_ai_content_security_audit_results', 'r');
    $query->fields('r', ['vector_id'])
      ->addExpression('AVG(score)', 'average_score')
      ->groupBy('vector_id');
    $results = $query->execute()
      ->fetchAllKeyed();

    return array_map('floatval', $results);
  }

  /**
   * Gets all configured security vectors.
   *
   * @return array
   *   Array of vector configurations keyed by vector_id.
   */
  public function getVectors(): array {
    $config = $this->configFactory->get('analyze_ai_content_security_audit.settings');
    return $config->get('vectors') ?? [];
  }

  /**
   * Gets a single security vector configuration.
   *
   * @param string $vector_id
   *   The vector ID.
   *
   * @return array|null
   *   The vector configuration or NULL if not found.
   */
  public function getVector(string $vector_id): ?array {
    $vectors = $this->getVectors();
    return $vectors[$vector_id] ?? NULL;
  }

  /**
   * Saves a security vector configuration.
   *
   * @param string $vector_id
   *   The vector ID.
   * @param array $vector_data
   *   The vector configuration data.
   */
  public function saveVector(string $vector_id, array $vector_data): void {
    $config = $this->configFactory->getEditable('analyze_ai_content_security_audit.settings');
    $vectors = $config->get('vectors') ?? [];
    $vectors[$vector_id] = $vector_data;
    $config->set('vectors', $vectors)->save();

    // Invalidate cache since configuration changed.
    $this->invalidateConfigCache();
  }

  /**
   * Deletes a security vector configuration.
   *
   * @param string $vector_id
   *   The vector ID to delete.
   */
  public function deleteVector(string $vector_id): void {
    $config = $this->configFactory->getEditable('analyze_ai_content_security_audit.settings');
    $vectors = $config->get('vectors') ?? [];

    if (isset($vectors[$vector_id])) {
      unset($vectors[$vector_id]);
      $config->set('vectors', $vectors)->save();

      // Delete all stored results for this vector.
      $this->database->delete('analyze_ai_content_security_audit_results')
        ->condition('vector_id', $vector_id)
        ->execute();

      // Invalidate cache since configuration changed.
      $this->invalidateConfigCache();
    }
  }

  /**
   * Generates a configuration hash for security vector settings.
   *
   * @return string
   *   The MD5 hash of the vector configuration.
   */
  public function generateConfigHash(): string {
    $config = $this->configFactory->get('analyze_ai_content_security_audit.settings');
    $vectors = $config->get('vectors') ?? [];

    // Sort to ensure consistent hashing.
    ksort($vectors);

    return hash('md5', serialize($vectors));
  }

  /**
   * Generates a content hash for an entity.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity to generate a hash for.
   *
   * @return string
   *   The SHA256 hash of the entity content.
   */
  private function generateContentHash(EntityInterface $entity): string {
    $content = $this->getEntityContent($entity);
    return hash('sha256', $content);
  }

  /**
   * Extracts clean text content from an entity.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity to extract content from.
   *
   * @return string
   *   The cleaned text content.
   */
  private function getEntityContent(EntityInterface $entity): string {
    // Use the entity's own language, not the current UI language.
    $langcode = $entity->language()->getId();

    // Render the entity in default view mode.
    $view_builder = $this->entityTypeManager->getViewBuilder($entity->getEntityTypeId());
    $view = $view_builder->view($entity, 'default', $langcode);
    $rendered = $this->renderer->render($view);

    // Convert to string and clean up.
    $content = is_object($rendered) && method_exists($rendered, '__toString')
      ? $rendered->__toString()
      : (string) $rendered;

    // Strip HTML tags and normalize whitespace.
    $content = strip_tags($content);
    $content = str_replace('&nbsp;', ' ', $content);
    $content = preg_replace('/\s+/', ' ', $content);
    $content = trim($content);

    return $content;
  }

}
