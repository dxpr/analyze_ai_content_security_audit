<?php

namespace Drupal\analyze_ai_content_security_audit\Form;

use Drupal\Core\Url;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Configure security vector analysis settings.
 */
class SecurityVectorSettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'analyze_ai_content_security_audit_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    /** @var array<string> */
    return ['analyze_ai_content_security_audit.settings'];
  }

  /**
   * Gets the default security vector configurations.
   *
   * @return array<string, array<string, mixed>>
   *   Array of default vector configurations.
   */
  public function getDefaultVectors(): array {
    return [
      'pii_disclosure' => [
        'label' => $this->t('PII Disclosure'),
        'description' => $this->t('Identifies potential disclosure of personally identifiable information (PII) in content.'),
        'weight' => 0,
      ],
      'credentials_disclosure' => [
        'label' => $this->t('Credentials Disclosure'),
        'description' => $this->t('Detects potential exposure of credentials, API keys, passwords, or other sensitive authentication data.'),
        'weight' => 10,
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    /** @var array<string, mixed> $form */
    $config = $this->config('analyze_ai_content_security_audit.settings');
    $vectors = $config->get('vectors') ?: $this->getDefaultVectors();

    $form['description'] = [
      '#type' => 'html_tag',
      '#tag' => 'div',
      '#attributes' => ['class' => ['security-vector-description']],
      'content' => [
        '#type' => 'html_tag',
        '#tag' => 'p',
        '#value' => $this->t('Configure the security vectors used to analyze content. Each vector analyzes for specific security risks with scores from 0 (no risk) to 100 (high risk).'),
      ],
    ];

    $form['table'] = [
      '#type' => 'container',
      '#attributes' => ['class' => ['security-vector-table-container']],
    ];

    $form['table']['vectors'] = [
      '#type' => 'table',
      '#header' => [
        $this->t('Security Vector'),
        $this->t('Description'),
        $this->t('Weight'),
        $this->t('Operations'),
      ],
      '#tabledrag' => [
        [
          'action' => 'order',
          'relationship' => 'sibling',
          'group' => 'vector-weight',
        ],
      ],
    ];

    // Sort vectors by weight.
    uasort($vectors, function ($a, $b) {
      return ($a['weight'] ?? 0) <=> ($b['weight'] ?? 0);
    });

    // Add existing vectors to the table.
    foreach ($vectors as $id => $vector) {
      $form['table']['vectors'][$id] = [
        '#attributes' => [
          'class' => ['draggable'],
        ],
        'label' => [
          '#type' => 'textfield',
          '#title' => $this->t('Label'),
          '#title_display' => 'invisible',
          '#default_value' => $vector['label'],
          '#required' => TRUE,
        ],
        'description' => [
          '#type' => 'textfield',
          '#title' => $this->t('Description'),
          '#title_display' => 'invisible',
          '#default_value' => $vector['description'],
          '#required' => TRUE,
          '#maxlength' => 255,
        ],
        'weight' => [
          '#type' => 'weight',
          '#title' => $this->t('Weight'),
          '#title_display' => 'invisible',
          '#default_value' => $vector['weight'],
          '#attributes' => ['class' => ['vector-weight']],
        ],
        'operations' => [
          '#type' => 'operations',
          '#links' => [
            'delete' => [
              'title' => $this->t('Delete'),
              'url' => Url::fromRoute('analyze_ai_content_security_audit.vector.delete', ['vector_id' => $id]),
              'attributes' => [
                'class' => ['button', 'button--danger', 'button--small'],
              ],
            ],
          ],
        ],
      ];
    }

    // Help text for drag-and-drop.
    if (!empty($vectors)) {
      $form['table_help'] = [
        '#type' => 'html_tag',
        '#tag' => 'p',
        '#value' => $this->t('Drag and drop rows to reorder the security vectors. This order will be reflected in the analysis display.'),
        '#attributes' => ['class' => ['vector-help-text', 'description']],
        '#weight' => 5,
      ];
    }

    $form = parent::buildForm($form, $form_state);

    // Improve the save button.
    $form['actions']['submit']['#value'] = $this->t('Save changes');
    $form['actions']['submit']['#attributes']['class'][] = 'button--primary';

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    /** @var array<string, mixed> $form */
    $vectors = [];
    foreach ($form_state->getValue('vectors') as $id => $values) {
      $vectors[$id] = [
        'label' => $values['label'],
        'description' => $values['description'],
        'weight' => $values['weight'],
      ];
    }

    $this->config('analyze_ai_content_security_audit.settings')
      ->set('vectors', $vectors)
      ->save();

    // Invalidate all cached security analysis results since configuration changed.
    \Drupal::service('analyze_ai_content_security_audit.storage')->invalidateConfigCache();

    parent::submitForm($form, $form_state);
  }

}