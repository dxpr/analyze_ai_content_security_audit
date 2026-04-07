<?php

namespace Drupal\analyze_ai_content_security_audit\Form;

use Drupal\analyze_ai_content_security_audit\Service\SecurityVectorStorageService;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Configure security vector analysis settings.
 */
class SecurityVectorSettingsForm extends ConfigFormBase {

  /**
   * The current user.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected AccountProxyInterface $currentUser;

  /**
   * The security vector storage service.
   *
   * @var \Drupal\analyze_ai_content_security_audit\Service\SecurityVectorStorageService
   */
  protected SecurityVectorStorageService $storage;

  /**
   * Constructs a SecurityVectorSettingsForm object.
   *
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   *   The current user.
   * @param \Drupal\analyze_ai_content_security_audit\Service\SecurityVectorStorageService $storage
   *   The security vector storage service.
   */
  final public function __construct(AccountProxyInterface $current_user, SecurityVectorStorageService $storage) {
    $this->currentUser = $current_user;
    $this->storage = $storage;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('current_user'),
      $container->get('analyze_ai_content_security_audit.storage')
    );
  }

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

    // Add link to reports page if user has permission.
    if ($this->currentUser->hasPermission('access site reports')) {
      $reports_url = Url::fromRoute('view.ai_content_security_audit_results.page_1');
      if ($reports_url->access()) {
        $form['actions_top'] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['form-actions']],
          '#weight' => -10,
          'report_link' => [
            '#type' => 'link',
            '#title' => $this->t('View reports'),
            '#url' => $reports_url,
            '#attributes' => [
              'class' => ['button', 'button--small', 'button--primary'],
            ],
          ],
        ];
      }
    }

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

    // Invalidate all cached security analysis results since configuration
    // changed.
    $this->storage->invalidateConfigCache();

    parent::submitForm($form, $form_state);
  }

}
