<?php

namespace Drupal\analyze_ai_content_security_audit\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfirmFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\analyze_ai_content_security_audit\Service\SecurityVectorStorageService;

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
   * The storage service.
   *
   * @var \Drupal\analyze_ai_content_security_audit\Service\SecurityVectorStorageService
   */
  protected $storage;

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
   * @param \Drupal\analyze_ai_content_security_audit\Service\SecurityVectorStorageService $storage
   *   The storage service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, SecurityVectorStorageService $storage) {
    $this->configFactory = $config_factory;
    $this->storage = $storage;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new self(
          $container->get('config.factory'),
          $container->get('analyze_ai_content_security_audit.storage')
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
   *
   * @param array<string, mixed> $form
   *   An associative array containing the structure of the form.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current state of the form.
   * @param string|null $vector_id
   *   The security vector ID to delete.
   *
   * @return array<string, mixed>
   *   The form structure.
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
   *
   * @param array<string, mixed> $form
   *   An associative array containing the structure of the form.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current state of the form.
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    /** @var array<string, mixed> $form */
    $storage = $this->storage;

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
