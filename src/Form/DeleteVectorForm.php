<?php

namespace Drupal\analyze_ai_content_security_audit\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfirmFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Provides a form for deleting a security vector.
 */
class DeleteVectorForm extends ConfirmFormBase {

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The vector ID to delete.
   *
   * @var string
   */
  protected $vectorId;

  /**
   * Constructs a DeleteVectorForm object.
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
    return 'analyze_ai_content_security_audit_delete_vector';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, ?string $vector_id = NULL): array {
    /** @var array<string, mixed> $form */
    $this->vectorId = $vector_id;
    $form = parent::buildForm($form, $form_state);

    // Add warning class to confirm button.
    $form['actions']['submit']['#attributes']['class'][] = 'button--danger';

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function getQuestion() {
    $config = $this->configFactory->get('analyze_ai_content_security_audit.settings');
    $vectors = $config->get('vectors');
    $vector = $vectors[$this->vectorId] ?? NULL;

    return $this->t('Are you sure you want to delete the security vector %label?', [
      '%label' => $vector ? $vector['label'] : $this->vectorId,
    ]);
  }

  /**
   * {@inheritdoc}
   */
  public function getDescription() {
    return $this->t('This action cannot be undone. All content analysis results using this security vector will be permanently deleted.');
  }

  /**
   * {@inheritdoc}
   */
  public function getCancelText() {
    return $this->t('Keep security vector');
  }

  /**
   * {@inheritdoc}
   */
  public function getConfirmText() {
    return $this->t('Delete security vector');
  }

  /**
   * {@inheritdoc}
   */
  public function getCancelUrl() {
    return new Url('analyze_ai_content_security_audit.settings');
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    /** @var array<string, mixed> $form */
    $storage = \Drupal::service('analyze_ai_content_security_audit.storage');

    $config = $this->configFactory->get('analyze_ai_content_security_audit.settings');
    $vectors = $config->get('vectors');

    if (isset($vectors[$this->vectorId])) {
      $label = $vectors[$this->vectorId]['label'];

      // Use storage service to properly delete vector and associated data.
      $storage->deleteVector($this->vectorId);

      $this->messenger()->addStatus($this->t('The security vector %label has been deleted.', [
        '%label' => $label,
      ]));
    }

    $form_state->setRedirectUrl($this->getCancelUrl());
  }

}
