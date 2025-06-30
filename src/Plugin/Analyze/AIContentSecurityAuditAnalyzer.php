<?php

namespace Drupal\analyze_ai_content_security_audit\Plugin\Analyze;

use Drupal\ai\AiProviderPluginManager;
use Drupal\ai\OperationType\Chat\ChatInput;
use Drupal\ai\OperationType\Chat\ChatMessage;
use Drupal\ai\Service\PromptJsonDecoder\PromptJsonDecoderInterface;
use Drupal\analyze\AnalyzePluginBase;
use Drupal\analyze_ai_content_security_audit\Service\SecurityVectorStorageService;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Link;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Render\RendererInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * A security analyzer that uses AI to analyze content security risks.
 *
 * @Analyze(
 *   id = "analyze_ai_content_security_audit_analyzer",
 *   label = @Translation("Content Security Audit"),
 *   description = @Translation("Analyzes content for security risks using AI.")
 * )
 */
final class AIContentSecurityAuditAnalyzer extends AnalyzePluginBase {

  /**
   * The AI provider manager.
   *
   * @var \Drupal\ai\AiProviderPluginManager
   */
  protected $aiProvider;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface|null
   */
  protected ?ConfigFactoryInterface $configFactory;

  /**
   * The messenger service.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  protected $messenger;

  /**
   * The prompt JSON decoder service.
   *
   * @var \Drupal\ai\Service\PromptJsonDecoder\PromptJsonDecoderInterface
   */
  protected PromptJsonDecoderInterface $promptJsonDecoder;

  /**
   * The security vector storage service.
   *
   * @var \Drupal\analyze_ai_content_security_audit\Service\SecurityVectorStorageService
   */
  protected SecurityVectorStorageService $storage;

  /**
   * Creates the plugin.
   *
   * @param array<string, mixed> $configuration
   *   Configuration.
   * @param string $plugin_id
   *   Plugin ID.
   * @param array<string, mixed> $plugin_definition
   *   Plugin Definition.
   * @param \Drupal\analyze\HelperInterface $helper
   *   Analyze helper service.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user.
   * @param \Drupal\ai\AiProviderPluginManager $aiProvider
   *   The AI provider manager.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   Config factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   Entity type manager.
   * @param \Drupal\Core\Render\RendererInterface $renderer
   *   The renderer service.
   * @param \Drupal\Core\Language\LanguageManagerInterface $languageManager
   *   The language manager service.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param \Drupal\ai\Service\PromptJsonDecoder\PromptJsonDecoderInterface $promptJsonDecoder
   *   The prompt JSON decoder service.
   * @param \Drupal\analyze_ai_content_security_audit\Service\SecurityVectorStorageService $storage
   *   The security vector storage service.
   */
  public function __construct(
    array $configuration,
    $plugin_id,
    $plugin_definition,
    $helper,
    $currentUser,
    AiProviderPluginManager $aiProvider,
    ?ConfigFactoryInterface $config_factory,
    protected EntityTypeManagerInterface $entityTypeManager,
    protected RendererInterface $renderer,
    protected LanguageManagerInterface $languageManager,
    MessengerInterface $messenger,
    PromptJsonDecoderInterface $promptJsonDecoder,
    SecurityVectorStorageService $storage,
  ) {
    parent::__construct($configuration, $plugin_id, $plugin_definition, $helper, $currentUser);
    $this->aiProvider = $aiProvider;
    $this->configFactory = $config_factory;
    $this->messenger = $messenger;
    $this->promptJsonDecoder = $promptJsonDecoder;
    $this->storage = $storage;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): static {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('analyze.helper'),
      $container->get('current_user'),
      $container->get('ai.provider'),
      $container->get('config.factory'),
      $container->get('entity_type.manager'),
      $container->get('renderer'),
      $container->get('language_manager'),
      $container->get('messenger'),
      $container->get('ai.prompt_json_decode'),
      $container->get('analyze_ai_content_security_audit.storage'),
    );
  }

  /**
   * Get configured security vectors.
   *
   * @return array
   *   Array of vector configurations.
   */
  protected function getConfiguredVectors(): array {
    $vectors = $this->storage->getVectors();

    if (empty($vectors)) {
      // Load defaults from the settings form.
      $form = \Drupal::classResolver()
        ->getInstanceFromDefinition('\Drupal\analyze_ai_content_security_audit\Form\SecurityVectorSettingsForm');
      return $form->getDefaultVectors();
    }

    return $vectors;
  }

  /**
   * Gets the enabled vectors for an entity type and bundle.
   *
   * @param string $entity_type_id
   *   The entity type ID.
   * @param string|null $bundle
   *   The bundle ID.
   *
   * @return array
   *   Array of enabled vector IDs.
   */
  protected function getEnabledVectors(string $entity_type_id, ?string $bundle = NULL): array {
    if (!$this->isEnabledForEntityType($entity_type_id, $bundle)) {
      return [];
    }

    // Get settings from plugin_settings config.
    $plugin_settings_config = $this->getConfigFactory()->get('analyze.plugin_settings');
    $key = sprintf('%s.%s.%s', $entity_type_id, $bundle, $this->getPluginId());
    $settings = $plugin_settings_config->get($key) ?? [];

    // Get all available vectors.
    $vectors = $this->getConfiguredVectors();

    $enabled = [];
    foreach ($vectors as $id => $vector) {
      // If no settings exist yet, enable all vectors by default.
      if (!isset($settings['vectors'])) {
        $enabled[$id] = $vector;
      }
      // Otherwise check if explicitly enabled in settings.
      elseif (isset($settings['vectors'][$id]) && $settings['vectors'][$id]) {
        $enabled[$id] = $vector;
      }
    }

    // Sort enabled vectors by weight.
    uasort($enabled, function ($a, $b) {
      return ($a['weight'] ?? 0) <=> ($b['weight'] ?? 0);
    });

    return $enabled;
  }

  /**
   * Creates a fallback status table.
   *
   * @param string $message
   *   The status message to display.
   *
   * @return array
   *   The render array for the status table.
   */
  private function createStatusTable(string $message): array {
    // If this is the AI provider message and user has permission,
    // append the settings link.
    if ($message === 'No chat AI provider is configured for security analysis.' && $this->currentUser->hasPermission('administer analyze settings')) {
      $link = Link::createFromRoute($this->t('Configure AI provider'), 'ai.settings_form');
      $message = $this->t('No chat AI provider is configured for security analysis. @link to set up AI services for security analysis.', ['@link' => $link->toString()]);
    }

    return [
      '#theme' => 'analyze_table',
      '#table_title' => 'Content Security Audit',
      '#rows' => [
        [
          'label' => 'Status',
          'data' => $message,
        ],
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function renderSummary(EntityInterface $entity): array {
    $status_config = $this->getConfigFactory()->get('analyze.settings');
    $status = $status_config->get('status') ?? [];
    $entity_type = $entity->getEntityTypeId();
    $bundle = $entity->bundle();

    if (!isset($status[$entity_type][$bundle][$this->getPluginId()])) {
      $settings_link = Link::createFromRoute($this->t('Enable content security audit'), 'analyze.analyze_settings')->toString();
      return $this->createStatusTable($this->t('Content security audit is not enabled for this content type. @link to configure content types.', ['@link' => $settings_link]));
    }

    $enabled_vectors = $this->getEnabledVectors($entity->getEntityTypeId(), $entity->bundle());
    if (empty($enabled_vectors)) {
      $vectors_link = Link::createFromRoute($this->t('Configure security vectors'), 'analyze_ai_content_security_audit.settings')->toString();
      return $this->createStatusTable($this->t('No security vectors are currently enabled. @link to select security vectors to analyze.', ['@link' => $vectors_link]));
    }

    // Try to get cached scores first.
    $scores = $this->storage->getScores($entity);

    // If no cached scores, perform analysis.
    if (empty($scores)) {
      $scores = $this->analyzeSecurityRisks($entity);
      if (!empty($scores)) {
        $this->storage->saveScores($entity, $scores);
      }
    }

    // Show the highest risk score as a gauge.
    if (!empty($scores)) {
      $max_score = max($scores);
      $vector_id = array_search($max_score, $scores);
      $vector = $enabled_vectors[$vector_id] ?? reset($enabled_vectors);

      // Convert 0 to 100 range to 0 to 1 for gauge.
      $gauge_value = $max_score / 100;

      return [
        '#theme' => 'analyze_gauge',
        '#caption' => $this->t('Security Risk Level'),
        '#range_min_label' => $this->t('No Risk'),
        '#range_mid_label' => $this->t('Medium Risk'),
        '#range_max_label' => $this->t('High Risk'),
        '#range_min' => 0,
        '#range_max' => 100,
        '#value' => $gauge_value,
        '#display_value' => sprintf('%d', $max_score),
      ];
    }

    // If no scores available but everything is configured correctly,
    // show a helpful message.
    if (!empty($content = $this->getHtml($entity))) {
      $ai_link = Link::createFromRoute($this->t('Configure AI provider'), 'ai.settings_form')->toString();
      return $this->createStatusTable($this->t('No chat AI provider is configured for security analysis. @link to set up AI services.', ['@link' => $ai_link]));
    }

    return $this->createStatusTable($this->t('This content has no text available for security analysis. Add content such as body text, fields, or descriptions to enable analysis.'));
  }

  /**
   * {@inheritdoc}
   */
  public function renderFullReport(EntityInterface $entity): array {
    $status_config = $this->getConfigFactory()->get('analyze.settings');
    $status = $status_config->get('status') ?? [];
    $entity_type = $entity->getEntityTypeId();
    $bundle = $entity->bundle();

    if (!isset($status[$entity_type][$bundle][$this->getPluginId()])) {
      $settings_link = Link::createFromRoute($this->t('Enable content security audit'), 'analyze.analyze_settings')->toString();
      return $this->createStatusTable($this->t('Content security audit is not enabled for this content type. @link to configure content types.', ['@link' => $settings_link]));
    }

    $enabled_vectors = $this->getEnabledVectors($entity->getEntityTypeId(), $entity->bundle());
    if (empty($enabled_vectors)) {
      $vectors_link = Link::createFromRoute($this->t('Configure security vectors'), 'analyze_ai_content_security_audit.settings')->toString();
      return $this->createStatusTable($this->t('No security vectors are currently enabled. @link to select security vectors to analyze.', ['@link' => $vectors_link]));
    }

    // Try to get cached scores first.
    $scores = $this->storage->getScores($entity);

    // If no cached scores, perform analysis.
    if (empty($scores)) {
      $scores = $this->analyzeSecurityRisks($entity);
      if (!empty($scores)) {
        $this->storage->saveScores($entity, $scores);
      }
    }

    if (empty($scores)) {
      $ai_link = Link::createFromRoute($this->t('Configure AI provider'), 'ai.settings_form')->toString();
      return $this->createStatusTable($this->t('No chat AI provider is configured for security analysis. @link to set up AI services.', ['@link' => $ai_link]));
    }

    // Build gauges for each enabled vector.
    $build = [];
    foreach ($enabled_vectors as $id => $vector) {
      if (isset($scores[$id])) {
        // Convert 0 to 100 range to 0 to 1 for gauge.
        $gauge_value = $scores[$id] / 100;

        $build[$id] = [
          '#theme' => 'analyze_gauge',
          '#caption' => $this->t('@label', ['@label' => $vector['label']]),
          '#range_min_label' => $this->t('No Risk'),
          '#range_mid_label' => $this->t('Medium Risk'),
          '#range_max_label' => $this->t('High Risk'),
          '#range_min' => 0,
          '#range_max' => 100,
          '#value' => $gauge_value,
          '#display_value' => sprintf('%d', $scores[$id]),
        ];
      }
    }

    return $build;
  }

  /**
   * Helper to get the rendered entity content.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity to render.
   *
   * @return string
   *   A HTML string of rendered content.
   */
  private function getHtml(EntityInterface $entity): string {
    // Get the current active langcode from the site.
    $langcode = $this->languageManager->getCurrentLanguage()->getId();

    // Get the rendered entity view in default mode.
    $view = $this->entityTypeManager->getViewBuilder($entity->getEntityTypeId())->view($entity, 'default', $langcode);
    $rendered = $this->renderer->render($view);

    // Convert to string and strip HTML for security analysis.
    $content = is_object($rendered) && method_exists($rendered, '__toString')
      ? $rendered->__toString()
      : (string) $rendered;

    // Clean up the content for security analysis.
    $content = strip_tags($content);
    $content = str_replace('&nbsp;', ' ', $content);
    // Replace multiple whitespace characters (spaces, tabs, newlines)
    // with a single space.
    $content = preg_replace('/\s+/', ' ', $content);
    $content = trim($content);

    return $content;
  }

  /**
   * Analyze the security risks of entity content.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity to analyze.
   *
   * @return array
   *   Array with security risk scores.
   */
  protected function analyzeSecurityRisks(EntityInterface $entity): array {
    try {
      // Get the content to analyze.
      $content = $this->getHtml($entity);

      // Get the AI provider.
      $ai_provider = $this->getAiProvider();
      if (!$ai_provider) {
        return [];
      }

      // Get the default model.
      $defaults = $this->getDefaultModel();
      if (!$defaults) {
        return [];
      }

      // Build the prompt.
      $enabled_vectors = $this->getEnabledVectors($entity->getEntityTypeId(), $entity->bundle());

      // Build vector descriptions with their analysis criteria.
      $vector_descriptions = [];
      foreach ($enabled_vectors as $id => $vector) {
        $criteria = $this->getVectorCriteria($id);
        $vector_descriptions[] = sprintf(
          "- %s: %s (Score 0-100, where 0=no risk, 100=high risk)",
          $vector['label'],
          $criteria
        );
      }

      // Build dynamic JSON structure based on enabled vectors.
      $json_keys = array_map(function ($id, $vector) {
        return '"' . $id . '": number';
      }, array_keys($enabled_vectors), $enabled_vectors);

      $json_template = '{' . implode(', ', $json_keys) . '}';

      $vectors = implode("\n", $vector_descriptions);

      $prompt = <<<EOT
<task>Analyze the following content for security risks.</task>
<content>
$content
</content>

<security_vectors>
$vectors
</security_vectors>

<instructions>Provide precise risk scores between 0 and 100 for each security vector. Use any integer values that best represent the risk level.</instructions>
<output_format>Respond with a simple JSON object containing only the required scores:
$json_template</output_format>
EOT;

      $chat_array = [
        new ChatMessage('user', $prompt),
      ];

      // Get response.
      $messages = new ChatInput($chat_array);
      $message = $ai_provider->chat($messages, $defaults['model_id'])->getNormalized();

      // Use the injected PromptJsonDecoder service.
      $decoded = $this->promptJsonDecoder->decode($message);

      // If we couldn't decode the JSON at all.
      if (!is_array($decoded)) {
        return [];
      }

      // Validate and normalize scores to ensure they're within 0 to 100 range.
      $scores = [];
      foreach ($enabled_vectors as $id => $vector) {
        if (isset($decoded[$id])) {
          $score = (int) $decoded[$id];
          // Clamp score to 0 to 100 range.
          $scores[$id] = max(0, min(100, $score));
        }
      }

      return $scores;

    }
    catch (\Exception $e) {
      return [];
    }
  }

  /**
   * Gets the analysis criteria for a specific security vector.
   *
   * @param string $vector_id
   *   The vector ID.
   *
   * @return string
   *   The analysis criteria description.
   */
  private function getVectorCriteria(string $vector_id): string {
    $criteria = [
      'pii_disclosure' => 'Analyze for potential disclosure of personally identifiable information including names, addresses, phone numbers, email addresses, social security numbers, credit card numbers, or other personal data',
      'credentials_disclosure' => 'Detect potential exposure of credentials, API keys, passwords, tokens, access keys, database connection strings, or other sensitive authentication data',
    ];

    return $criteria[$vector_id] ?? 'Analyze for general security risks in the content';
  }

  /**
   * Gets the public settings for this analyzer.
   *
   * @param string $entity_type_id
   *   The entity type ID.
   * @param string|null $bundle
   *   The bundle ID.
   *
   * @return array
   *   The settings array.
   */
  public function getSettings(string $entity_type_id, ?string $bundle = NULL): array {
    return $this->getEntityTypeSettings($entity_type_id, $bundle);
  }

  /**
   * {@inheritdoc}
   */
  public function saveSettings(string $entity_type_id, ?string $bundle, array $settings): void {
    $config = \Drupal::configFactory()->getEditable('analyze.settings');
    $current = $config->get('status') ?? [];

    // Save enabled state.
    if (isset($settings['enabled'])) {
      $current[$entity_type_id][$bundle][$this->getPluginId()] = $settings['enabled'];
      $config->set('status', $current)->save();
    }

    // Save vector settings if present.
    if (isset($settings['vectors'])) {
      $detailed_config = \Drupal::configFactory()->getEditable('analyze.plugin_settings');
      $key = sprintf('%s.%s.%s', $entity_type_id, $bundle, $this->getPluginId());
      $detailed_config->set($key, ['vectors' => $settings['vectors']])->save();
    }
  }

  /**
   * Gets the default settings structure.
   *
   * @return array
   *   The default settings structure.
   */
  public function getDefaultSettings(): array {
    $vectors = $this->getConfiguredVectors();
    $default_vectors = [];

    foreach ($vectors as $id => $vector) {
      $default_vectors[$id] = TRUE;
    }

    return [
      'enabled' => TRUE,
      'settings' => [
        'vectors' => $default_vectors,
      ],
    ];
  }

  /**
   * Gets the configurable settings for this analyzer.
   *
   * Defines the form elements for configuring security vectors.
   *
   * @return array
   *   An array of configurable settings.
   */
  public function getConfigurableSettings(): array {
    $vectors = $this->getConfiguredVectors();
    $settings = [];

    foreach ($vectors as $id => $vector) {
      $settings[$id] = [
        'type' => 'checkbox',
        'title' => $vector['label'],
        'default_value' => TRUE,
      ];
    }

    return [
      'vectors' => [
        'type' => 'fieldset',
        'title' => $this->t('Security Vectors'),
        'description' => $this->t('Select which security vectors to analyze.'),
        'settings' => $settings,
      ],
    ];
  }

  /**
   * Gets the AI provider instance configured for chat operations.
   *
   * @return \Drupal\ai\AiProviderInterface|null
   *   The configured AI provider, or NULL if none available.
   */
  private function getAiProvider() {
    // Check if we have any chat providers available.
    if (!$this->aiProvider->hasProvidersForOperationType('chat', TRUE)) {
      return NULL;
    }

    // Get the default provider for chat.
    $defaults = $this->getDefaultModel();
    if (empty($defaults['provider_id'])) {
      return NULL;
    }

    // Initialize AI provider.
    $ai_provider = $this->aiProvider->createInstance($defaults['provider_id']);

    // Configure provider with low temperature for more consistent results.
    $ai_provider->setConfiguration(['temperature' => 0.2]);

    return $ai_provider;
  }

  /**
   * Gets the default model configuration for chat operations.
   *
   * @return array|null
   *   Array containing provider_id and model_id, or NULL if not configured.
   */
  private function getDefaultModel() {
    $defaults = $this->aiProvider->getDefaultProviderForOperationType('chat');
    if (empty($defaults['provider_id']) || empty($defaults['model_id'])) {
      return NULL;
    }
    return $defaults;
  }

}
