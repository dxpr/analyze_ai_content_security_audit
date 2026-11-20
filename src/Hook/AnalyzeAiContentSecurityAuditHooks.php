<?php

namespace Drupal\analyze_ai_content_security_audit\Hook;

use Drupal\Core\Session\AccountProxyInterface;

use Drupal\Core\Link;
use Drupal\Core\Url;
use Drupal\views\ViewExecutable;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\StringTranslation\StringTranslationTrait;

/**
 * Hook implementations for analyze_ai_content_security_audit.
 */
class AnalyzeAiContentSecurityAuditHooks {
  use StringTranslationTrait;

  /**
   * Constructs the hook service.
   */
  public function __construct(
    protected AccountProxyInterface $currentUser,
  ) {}

  /**
   * Implements hook_views_pre_view().
   */
  #[Hook('views_pre_view')]
  public function viewsPreView(ViewExecutable $view, $display_id, array &$args) {
    // Add settings link to the content security audit view header.
    if ($view->id() === 'ai_content_security_audit_results' && $display_id === 'page_1') {
      // Build the settings link if user has permission.
      $current_user = $this->currentUser;
      if ($current_user->hasPermission('administer analyze')) {
        $settings_url = Url::fromRoute('analyze_ai_content_security_audit.settings');
        if ($settings_url->access()) {
          $link = Link::fromTextAndUrl($this->t('Configure settings'), $settings_url);
          $link = $link->toRenderable();
          $link['#attributes']['class'][] = 'button';
          $link['#attributes']['class'][] = 'button--small';
          $link['#attributes']['class'][] = 'button--primary';
          // Add content before the view using attachment_before as render array.
          $view->attachment_before = [
            '#type' => 'container',
            '#attributes' => [
              'class' => [
                'form-actions',
                'views-configure-actions',
              ],
            ],
            '#weight' => -10,
            'configure_link' => $link,
            '#attached' => [
              'library' => [
                'system/base',
              ],
            ],
          ];
        }
      }
    }
  }

  /**
   * Implements hook_views_color_scale_popover_alter().
   */
  #[Hook('views_color_scale_popover_alter')]
  public function viewsColorScalePopoverAlter(array &$content, array $context): void {
    if ($context['view']->storage->get('base_table') !== 'analyze_ai_content_security_audit_results') {
      return;
    }
    $content = [
      '#theme' => 'analyze_gauge',
      '#caption' => $context['field_options']['label'] ?? '',
      '#range_min_label' => $this->t('No Risk'),
      '#range_mid_label' => $this->t('Medium Risk'),
      '#range_max_label' => $this->t('High Risk'),
      '#range_min' => $context['min'],
      '#value' => $context['position'],
      '#display_value' => $context['display_value'],
      '#range_max' => $context['max'],
      '#attached' => [
        'library' => [
          'analyze/gauge-popover',
        ],
      ],
    ];
  }

}
