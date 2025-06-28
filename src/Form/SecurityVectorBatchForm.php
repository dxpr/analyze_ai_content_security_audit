<?php

declare(strict_types=1);

namespace Drupal\analyze_ai_content_security_audit\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\analyze_ai_content_security_audit\Service\SecurityVectorBatchService;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Batch form for security vector analysis.
 */
final class SecurityVectorBatchForm extends FormBase {

  public function __construct(
    private readonly SecurityVectorBatchService $batchService,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('analyze_ai_content_security_audit.batch_service'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'analyze_ai_content_security_audit_batch';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $form['description'] = [
      '#markup' => $this->t('<p>Analyze content for security risks. Results are cached to improve performance. Only published content will be analyzed.</p>'),
    ];

    $available_bundles = $this->batchService->getAvailableEntityBundles();
    
    if (empty($available_bundles)) {
      $configure_url = \Drupal\Core\Url::fromRoute('analyze.analyze_settings');
      $form['no_bundles'] = [
        '#markup' => $this->t('<p>No content types have security analysis enabled. Please <a href="@url">configure the Analyze module</a> first.</p>', [
          '@url' => $configure_url->toString(),
        ]),
      ];
      return $form;
    }

    $form['entity_types'] = [
      '#type' => 'checkboxes',
      '#title' => $this->t('Content Types'),
      '#description' => $this->t('Select which content types to analyze for security risks.'),
      '#options' => $available_bundles,
      '#required' => TRUE,
    ];

    $form['force_refresh'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Force re-analysis'),
      '#description' => $this->t('Re-analyze content even if recent results exist. This will replace all cached results.'),
    ];

    $form['limit'] = [
      '#type' => 'number',
      '#title' => $this->t('Limit'),
      '#description' => $this->t('Maximum number of entities to analyze (0 for no limit).'),
      '#default_value' => 100,
      '#min' => 0,
      '#max' => 10000,
    ];

    $form['actions'] = [
      '#type' => 'actions',
      'submit' => [
        '#type' => 'submit',
        '#value' => $this->t('Start Security Analysis'),
        '#button_type' => 'primary',
      ],
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $values = $form_state->getValues();
    $selected_types = array_filter($values['entity_types']);
    
    $entities = $this->batchService->getEntitiesForAnalysis(
      $selected_types,
      $values['force_refresh'],
      $values['limit']
    );
    
    if (empty($entities)) {
      $this->messenger()->addWarning($this->t('No entities found for analysis.'));
      return;
    }

    $batch = [
      'title' => $this->t('Analyzing Content Security'),
      'operations' => [],
      'finished' => [static::class, 'batchFinished'],
    ];

    // Process in chunks of 5.
    $chunks = array_chunk($entities, 5);
    foreach ($chunks as $chunk) {
      $batch['operations'][] = [
        [$this->batchService, 'processBatch'],
        [$chunk, $values['force_refresh']],
      ];
    }

    batch_set($batch);
  }

  /**
   * Batch finished callback.
   *
   * @param bool $success
   *   Whether the batch completed successfully.
   * @param array $results
   *   The batch results.
   * @param array $operations
   *   The batch operations.
   */
  public static function batchFinished(bool $success, array $results, array $operations): void {
    if ($success) {
      $processed = $results['processed'] ?? 0;
      \Drupal::messenger()->addStatus(t('Successfully analyzed @count entities.', [
        '@count' => $processed,
      ]));

      if (!empty($results['errors'])) {
        foreach ($results['errors'] as $error) {
          \Drupal::messenger()->addError($error);
        }
      }
    } else {
      \Drupal::messenger()->addError(t('Batch processing failed.'));
    }
  }

}