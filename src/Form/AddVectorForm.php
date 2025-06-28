<?php

namespace Drupal\analyze_ai_content_security_audit\Form;

use Drupal\Core\Url;
use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Form for adding a new security vector.
 */
class AddVectorForm extends FormBase {

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * Constructs a new AddVectorForm.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   */
  public function __construct(ConfigFactoryInterface $config_factory) {
    $this->configFactory = $config_factory;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'analyze_ai_content_security_audit_add_vector';
  }

  /**
   * Check if a security vector ID already exists.
   *
   * @param string $id
   *   The vector ID to check.
   *
   * @return bool
   *   TRUE if the vector exists, FALSE otherwise.
   */
  public function vectorExists($id) {
    $config = $this->configFactory->get('analyze_ai_content_security_audit.settings');
    $vectors = $config->get('vectors') ?: [];
    return isset($vectors[$id]);
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    /** @var array<string, mixed> $form */
    $form['description'] = [
      '#type' => 'html_tag',
      '#tag' => 'p',
      '#value' => $this->t('Add a new security vector to analyze content. Each vector analyzes for specific security risks with scores from 0 (no risk) to 100 (high risk).'),
    ];

    $form['basic'] = [
      '#type' => 'container',
      '#attributes' => ['class' => ['vector-basic-info']],
    ];

    $form['basic']['label'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Label'),
      '#required' => TRUE,
      '#description' => $this->t('The human-readable name for this security vector.'),
      '#placeholder' => $this->t('e.g., PII Disclosure'),
      '#maxlength' => 255,
    ];

    $form['basic']['id'] = [
      '#type' => 'machine_name',
      '#title' => $this->t('ID'),
      '#required' => TRUE,
      '#description' => $this->t('A unique machine-readable name. Can only contain lowercase letters, numbers, and underscores.'),
      '#machine_name' => [
        'exists' => [$this, 'vectorExists'],
        'source' => ['basic', 'label'],
      ],
    ];

    $form['basic']['description'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Description'),
      '#required' => TRUE,
      '#description' => $this->t('Describe what this security vector analyzes for.'),
      '#placeholder' => $this->t('e.g., Identifies potential disclosure of personally identifiable information (PII) in content.'),
      '#maxlength' => 255,
    ];

    $form['actions'] = [
      '#type' => 'actions',
      '#attributes' => ['class' => ['vector-form-actions']],
    ];

    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Add Security Vector'),
      '#button_type' => 'primary',
    ];

    $form['actions']['cancel'] = [
      '#type' => 'link',
      '#title' => $this->t('Cancel'),
      '#url' => Url::fromRoute('analyze_ai_content_security_audit.settings'),
      '#attributes' => [
        'class' => ['button', 'dialog-cancel'],
        'role' => 'button',
      ],
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    /** @var array<string, mixed> $form */
    $config = $this->configFactory->getEditable('analyze_ai_content_security_audit.settings');
    $vectors = $config->get('vectors') ?: [];

    // Get the maximum weight and add 1.
    $max_weight = 0;
    foreach ($vectors as $vector) {
      $max_weight = max($max_weight, $vector['weight'] ?? 0);
    }

    $values = $form_state->getValues();
    $vectors[$values['id']] = [
      'id' => $values['id'],
      'label' => $values['label'],
      'description' => $values['description'],
      'weight' => $max_weight + 1,
    ];

    $config->set('vectors', $vectors)->save();
    $this->messenger()->addStatus($this->t('Added new security vector %label.', ['%label' => $values['label']]));
    $form_state->setRedirectUrl(Url::fromRoute('analyze_ai_content_security_audit.settings'));
  }

}