<?php
// source: phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/conf/config.neon
// source: phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/conf/config.level0.neon
// source: /Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../composer/composer/phpstan/rules.neon
// source: /Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../composer/pcre/extension.neon
// source: /Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../mglaman/phpstan-drupal/extension.neon
// source: /Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../mglaman/phpstan-drupal/rules.neon
// source: /Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../phpstan-deprecation-rules/rules.neon
// source: /Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../phpstan-phpunit/extension.neon
// source: /Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../phpstan-phpunit/rules.neon
// source: /Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/../phpstan-basic.neon
// source: array

/** @noinspection PhpParamsInspection,PhpMethodMayBeStaticInspection */

declare(strict_types=1);

class Container_b4e34e1e86 extends _PHPStan_ac6dae9b0\Nette\DI\Container
{
	protected $tags = [
		'phpstan.parser.richParserNodeVisitor' => [
			'04' => true,
			'05' => true,
			'06' => true,
			'07' => true,
			'08' => true,
			'09' => true,
			'010' => true,
			'011' => true,
			'012' => true,
			'013' => true,
			'014' => true,
			'015' => true,
			'016' => true,
			'017' => true,
			'018' => true,
			'019' => true,
			'020' => true,
			'021' => true,
			'022' => true,
			'089' => true,
			'090' => true,
		],
		'phpstan.stubFilesExtension' => ['044' => true, '046' => true, '047' => true, '048' => true, '0421' => true],
		'phpstan.diagnoseExtension' => ['092' => true],
		'phpstan.broker.dynamicMethodReturnTypeExtension' => [
			'0107' => true,
			'0108' => true,
			'0109' => true,
			'0120' => true,
			'0121' => true,
			'0230' => true,
			'0241' => true,
			'0247' => true,
			'0248' => true,
			'0253' => true,
			'0288' => true,
			'0316' => true,
			'0343' => true,
			'0344' => true,
			'0351' => true,
			'0352' => true,
			'0353' => true,
			'0354' => true,
			'0355' => true,
			'0356' => true,
			'0358' => true,
			'0399' => true,
			'0400' => true,
			'0407' => true,
			'0408' => true,
			'0409' => true,
			'0410' => true,
			'0411' => true,
			'0412' => true,
			'0413' => true,
			'0414' => true,
			'0415' => true,
			'0445' => true,
		],
		'phpstan.broker.allowedSubTypesClassReflectionExtension' => ['0118' => true],
		'phpstan.broker.propertiesClassReflectionExtension' => ['0119' => true, '0286' => true, '0419' => true],
		'phpstan.broker.operatorTypeSpecifyingExtension' => ['0176' => true],
		'phpstan.broker.dynamicFunctionReturnTypeExtension' => [
			'0189' => true,
			'0190' => true,
			'0191' => true,
			'0192' => true,
			'0193' => true,
			'0195' => true,
			'0196' => true,
			'0197' => true,
			'0198' => true,
			'0199' => true,
			'0201' => true,
			'0202' => true,
			'0203' => true,
			'0204' => true,
			'0205' => true,
			'0207' => true,
			'0208' => true,
			'0209' => true,
			'0210' => true,
			'0211' => true,
			'0212' => true,
			'0213' => true,
			'0214' => true,
			'0215' => true,
			'0216' => true,
			'0217' => true,
			'0218' => true,
			'0219' => true,
			'0220' => true,
			'0221' => true,
			'0223' => true,
			'0224' => true,
			'0227' => true,
			'0228' => true,
			'0232' => true,
			'0233' => true,
			'0235' => true,
			'0236' => true,
			'0238' => true,
			'0240' => true,
			'0242' => true,
			'0245' => true,
			'0246' => true,
			'0255' => true,
			'0256' => true,
			'0258' => true,
			'0259' => true,
			'0260' => true,
			'0261' => true,
			'0262' => true,
			'0263' => true,
			'0264' => true,
			'0265' => true,
			'0266' => true,
			'0267' => true,
			'0268' => true,
			'0269' => true,
			'0271' => true,
			'0288' => true,
			'0291' => true,
			'0292' => true,
			'0293' => true,
			'0294' => true,
			'0295' => true,
			'0297' => true,
			'0298' => true,
			'0299' => true,
			'0300' => true,
			'0301' => true,
			'0302' => true,
			'0303' => true,
			'0304' => true,
			'0305' => true,
			'0306' => true,
			'0307' => true,
			'0309' => true,
			'0310' => true,
			'0311' => true,
			'0312' => true,
			'0313' => true,
			'0314' => true,
			'0315' => true,
			'0317' => true,
			'0318' => true,
			'0319' => true,
			'0320' => true,
			'0321' => true,
			'0322' => true,
			'0323' => true,
			'0324' => true,
			'0325' => true,
			'0328' => true,
			'0337' => true,
			'0341' => true,
			'0342' => true,
			'0345' => true,
			'0346' => true,
			'0347' => true,
			'0348' => true,
			'0349' => true,
			'0350' => true,
		],
		'phpstan.typeSpecifier.functionTypeSpecifyingExtension' => [
			'0206' => true,
			'0222' => true,
			'0237' => true,
			'0275' => true,
			'0285' => true,
			'0289' => true,
			'0290' => true,
			'0308' => true,
			'0326' => true,
			'0327' => true,
			'0329' => true,
			'0330' => true,
			'0331' => true,
			'0332' => true,
			'0333' => true,
			'0334' => true,
			'0335' => true,
			'0336' => true,
			'0338' => true,
			'0340' => true,
			'0442' => true,
		],
		'phpstan.dynamicFunctionThrowTypeExtension' => ['0225' => true, '0270' => true, '0272' => true],
		'phpstan.broker.dynamicStaticMethodReturnTypeExtension' => [
			'0226' => true,
			'0229' => true,
			'0231' => true,
			'0244' => true,
			'0351' => true,
			'0357' => true,
			'0416' => true,
			'0417' => true,
			'0418' => true,
		],
		'phpstan.dynamicStaticMethodThrowTypeExtension' => [
			'0243' => true,
			'0249' => true,
			'0252' => true,
			'0281' => true,
			'0282' => true,
			'0283' => true,
			'0284' => true,
			'0287' => true,
		],
		'phpstan.dynamicMethodThrowTypeExtension' => ['0250' => true, '0251' => true, '0254' => true],
		'phpstan.functionParameterOutTypeExtension' => ['0273' => true, '0274' => true, '0276' => true],
		'phpstan.functionParameterClosureTypeExtension' => ['0277' => true],
		'phpstan.typeSpecifier.methodTypeSpecifyingExtension' => ['0296' => true, '0422' => true, '0443' => true],
		'phpstan.rules.rule' => [
			'0370' => true,
			'0371' => true,
			'0372' => true,
			'0373' => true,
			'0374' => true,
			'0375' => true,
			'0376' => true,
			'0377' => true,
			'0378' => true,
			'0380' => true,
			'0381' => true,
			'0382' => true,
			'0383' => true,
			'0384' => true,
			'0385' => true,
			'0386' => true,
			'0387' => true,
			'0388' => true,
			'0389' => true,
			'0390' => true,
			'0391' => true,
			'0392' => true,
			'0393' => true,
			'0394' => true,
			'0395' => true,
			'0430' => true,
			'0450' => true,
			'rules.0' => true,
			'rules.1' => true,
			'rules.10' => true,
			'rules.100' => true,
			'rules.101' => true,
			'rules.102' => true,
			'rules.103' => true,
			'rules.104' => true,
			'rules.105' => true,
			'rules.106' => true,
			'rules.107' => true,
			'rules.108' => true,
			'rules.109' => true,
			'rules.11' => true,
			'rules.110' => true,
			'rules.111' => true,
			'rules.112' => true,
			'rules.113' => true,
			'rules.114' => true,
			'rules.115' => true,
			'rules.116' => true,
			'rules.117' => true,
			'rules.118' => true,
			'rules.119' => true,
			'rules.12' => true,
			'rules.120' => true,
			'rules.121' => true,
			'rules.122' => true,
			'rules.123' => true,
			'rules.124' => true,
			'rules.125' => true,
			'rules.126' => true,
			'rules.127' => true,
			'rules.128' => true,
			'rules.129' => true,
			'rules.13' => true,
			'rules.130' => true,
			'rules.131' => true,
			'rules.132' => true,
			'rules.133' => true,
			'rules.134' => true,
			'rules.135' => true,
			'rules.136' => true,
			'rules.137' => true,
			'rules.138' => true,
			'rules.14' => true,
			'rules.15' => true,
			'rules.16' => true,
			'rules.17' => true,
			'rules.18' => true,
			'rules.19' => true,
			'rules.2' => true,
			'rules.20' => true,
			'rules.21' => true,
			'rules.22' => true,
			'rules.23' => true,
			'rules.24' => true,
			'rules.25' => true,
			'rules.26' => true,
			'rules.27' => true,
			'rules.28' => true,
			'rules.29' => true,
			'rules.3' => true,
			'rules.30' => true,
			'rules.31' => true,
			'rules.32' => true,
			'rules.33' => true,
			'rules.34' => true,
			'rules.35' => true,
			'rules.36' => true,
			'rules.37' => true,
			'rules.38' => true,
			'rules.39' => true,
			'rules.4' => true,
			'rules.40' => true,
			'rules.41' => true,
			'rules.42' => true,
			'rules.43' => true,
			'rules.44' => true,
			'rules.45' => true,
			'rules.46' => true,
			'rules.47' => true,
			'rules.48' => true,
			'rules.49' => true,
			'rules.5' => true,
			'rules.50' => true,
			'rules.51' => true,
			'rules.52' => true,
			'rules.53' => true,
			'rules.54' => true,
			'rules.55' => true,
			'rules.56' => true,
			'rules.57' => true,
			'rules.58' => true,
			'rules.59' => true,
			'rules.6' => true,
			'rules.60' => true,
			'rules.61' => true,
			'rules.62' => true,
			'rules.63' => true,
			'rules.64' => true,
			'rules.65' => true,
			'rules.66' => true,
			'rules.67' => true,
			'rules.68' => true,
			'rules.69' => true,
			'rules.7' => true,
			'rules.70' => true,
			'rules.71' => true,
			'rules.72' => true,
			'rules.73' => true,
			'rules.74' => true,
			'rules.75' => true,
			'rules.76' => true,
			'rules.77' => true,
			'rules.78' => true,
			'rules.79' => true,
			'rules.8' => true,
			'rules.80' => true,
			'rules.81' => true,
			'rules.82' => true,
			'rules.83' => true,
			'rules.84' => true,
			'rules.85' => true,
			'rules.86' => true,
			'rules.87' => true,
			'rules.88' => true,
			'rules.89' => true,
			'rules.9' => true,
			'rules.90' => true,
			'rules.91' => true,
			'rules.92' => true,
			'rules.93' => true,
			'rules.94' => true,
			'rules.95' => true,
			'rules.96' => true,
			'rules.97' => true,
			'rules.98' => true,
			'rules.99' => true,
		],
		'phpstan.staticMethodParameterOutTypeExtension' => ['0401' => true],
		'phpstan.typeSpecifier.staticMethodTypeSpecifyingExtension' => ['0402' => true, '0426' => true, '0444' => true],
		'phpstan.staticMethodParameterClosureTypeExtension' => ['0403' => true],
		'phpstan.broker.methodsClassReflectionExtension' => ['0420' => true],
		'phpstan.deprecations.deprecatedScopeResolver' => ['0423' => true, '0424' => true, '0425' => true, '0434' => true],
		'phpstan.restrictedClassConstantUsageExtension' => ['0436' => true],
		'phpstan.restrictedFunctionUsageExtension' => ['0437' => true],
		'phpstan.restrictedMethodUsageExtension' => ['0438' => true],
		'phpstan.restrictedPropertyUsageExtension' => ['0439' => true],
		'phpstan.restrictedClassNameUsageExtension' => ['0440' => true],
		'phpstan.phpDoc.typeNodeResolverExtension' => ['0441' => true],
	];

	protected $types = ['container' => '_PHPStan_ac6dae9b0\Nette\DI\Container'];
	protected $aliases = [];

	protected $wiring = [
		'_PHPStan_ac6dae9b0\Nette\DI\Container' => [['container']],
		'PHPStan\Rules\Rule' => [
			[
				'0142',
				'0143',
				'0144',
				'0161',
				'0177',
				'0370',
				'0371',
				'0372',
				'0373',
				'0374',
				'0375',
				'0376',
				'0377',
				'0378',
				'0379',
				'0380',
				'0381',
				'0382',
				'0383',
				'0384',
				'0385',
				'0386',
				'0387',
				'0388',
				'0389',
				'0390',
				'0391',
				'0392',
				'0393',
				'0394',
				'0395',
				'0427',
				'0428',
				'0429',
				'0430',
				'0431',
				'0435',
				'0450',
				'0451',
			],
			[
				'rules.0',
				'rules.1',
				'rules.2',
				'rules.3',
				'rules.4',
				'rules.5',
				'rules.6',
				'rules.7',
				'rules.8',
				'rules.9',
				'rules.10',
				'rules.11',
				'rules.12',
				'rules.13',
				'rules.14',
				'rules.15',
				'rules.16',
				'rules.17',
				'rules.18',
				'rules.19',
				'rules.20',
				'rules.21',
				'rules.22',
				'rules.23',
				'rules.24',
				'rules.25',
				'rules.26',
				'rules.27',
				'rules.28',
				'rules.29',
				'rules.30',
				'rules.31',
				'rules.32',
				'rules.33',
				'rules.34',
				'rules.35',
				'rules.36',
				'rules.37',
				'rules.38',
				'rules.39',
				'rules.40',
				'rules.41',
				'rules.42',
				'rules.43',
				'rules.44',
				'rules.45',
				'rules.46',
				'rules.47',
				'rules.48',
				'rules.49',
				'rules.50',
				'rules.51',
				'rules.52',
				'rules.53',
				'rules.54',
				'rules.55',
				'rules.56',
				'rules.57',
				'rules.58',
				'rules.59',
				'rules.60',
				'rules.61',
				'rules.62',
				'rules.63',
				'rules.64',
				'rules.65',
				'rules.66',
				'rules.67',
				'rules.68',
				'rules.69',
				'rules.70',
				'rules.71',
				'rules.72',
				'rules.73',
				'rules.74',
				'rules.75',
				'rules.76',
				'rules.77',
				'rules.78',
				'rules.79',
				'rules.80',
				'rules.81',
				'rules.82',
				'rules.83',
				'rules.84',
				'rules.85',
				'rules.86',
				'rules.87',
				'rules.88',
				'rules.89',
				'rules.90',
				'rules.91',
				'rules.92',
				'rules.93',
				'rules.94',
				'rules.95',
				'rules.96',
				'rules.97',
				'rules.98',
				'rules.99',
				'rules.100',
				'rules.101',
				'rules.102',
				'rules.103',
				'rules.104',
				'rules.105',
				'rules.106',
				'rules.107',
				'rules.108',
				'rules.109',
				'rules.110',
				'rules.111',
				'rules.112',
				'rules.113',
				'rules.114',
				'rules.115',
				'rules.116',
				'rules.117',
				'rules.118',
				'rules.119',
				'rules.120',
				'rules.121',
				'rules.122',
				'rules.123',
				'rules.124',
				'rules.125',
				'rules.126',
				'rules.127',
				'rules.128',
				'rules.129',
				'rules.130',
				'rules.131',
				'rules.132',
				'rules.133',
				'rules.134',
				'rules.135',
				'rules.136',
				'rules.137',
				'rules.138',
			],
		],
		'PHPStan\Rules\Debug\DebugScopeRule' => [['rules.0']],
		'PHPStan\Rules\Debug\DumpPhpDocTypeRule' => [['rules.1']],
		'PHPStan\Rules\Debug\DumpTypeRule' => [['rules.2']],
		'PHPStan\Rules\Debug\FileAssertRule' => [['rules.3']],
		'PHPStan\Rules\RestrictedUsage\RestrictedClassConstantUsageRule' => [['rules.4']],
		'PHPStan\Rules\RestrictedUsage\RestrictedFunctionUsageRule' => [['rules.5']],
		'PHPStan\Rules\RestrictedUsage\RestrictedFunctionCallableUsageRule' => [['rules.6']],
		'PHPStan\Rules\RestrictedUsage\RestrictedMethodUsageRule' => [['rules.7']],
		'PHPStan\Rules\RestrictedUsage\RestrictedMethodCallableUsageRule' => [['rules.8']],
		'PHPStan\Rules\RestrictedUsage\RestrictedPropertyUsageRule' => [['rules.9']],
		'PHPStan\Rules\RestrictedUsage\RestrictedStaticMethodUsageRule' => [['rules.10']],
		'PHPStan\Rules\RestrictedUsage\RestrictedStaticMethodCallableUsageRule' => [['rules.11']],
		'PHPStan\Rules\RestrictedUsage\RestrictedStaticPropertyUsageRule' => [['rules.12']],
		'PHPStan\Rules\RestrictedUsage\RestrictedUsageOfDeprecatedStringCastRule' => [['rules.13']],
		'PHPStan\Rules\Api\ApiInstanceofRule' => [['rules.14']],
		'PHPStan\Rules\Api\ApiInstanceofTypeRule' => [['rules.15']],
		'PHPStan\Rules\Api\ApiInstantiationRule' => [['rules.16']],
		'PHPStan\Rules\Api\ApiClassConstFetchRule' => [['rules.17']],
		'PHPStan\Rules\Api\ApiClassExtendsRule' => [['rules.18']],
		'PHPStan\Rules\Api\ApiClassImplementsRule' => [['rules.19']],
		'PHPStan\Rules\Api\ApiInterfaceExtendsRule' => [['rules.20']],
		'PHPStan\Rules\Api\ApiMethodCallRule' => [['rules.21']],
		'PHPStan\Rules\Api\ApiStaticCallRule' => [['rules.22']],
		'PHPStan\Rules\Api\ApiTraitUseRule' => [['rules.23']],
		'PHPStan\Rules\Api\GetTemplateTypeRule' => [['rules.24']],
		'PHPStan\Rules\Api\NodeConnectingVisitorAttributesRule' => [['rules.25']],
		'PHPStan\Rules\Api\OldPhpParser4ClassRule' => [['rules.26']],
		'PHPStan\Rules\Api\PhpStanNamespaceIn3rdPartyPackageRule' => [['rules.27']],
		'PHPStan\Rules\Api\RuntimeReflectionInstantiationRule' => [['rules.28']],
		'PHPStan\Rules\Api\RuntimeReflectionFunctionRule' => [['rules.29']],
		'PHPStan\Rules\Arrays\DuplicateKeysInLiteralArraysRule' => [['rules.30']],
		'PHPStan\Rules\Arrays\OffsetAccessWithoutDimForReadingRule' => [['rules.31']],
		'PHPStan\Rules\Cast\UnsetCastRule' => [['rules.32']],
		'PHPStan\Rules\Classes\AllowedSubTypesRule' => [['rules.33']],
		'PHPStan\Rules\Classes\ClassAttributesRule' => [['rules.34']],
		'PHPStan\Rules\Classes\ClassConstantAttributesRule' => [['rules.35']],
		'PHPStan\Rules\Classes\ClassConstantRule' => [['rules.36']],
		'PHPStan\Rules\Classes\DuplicateDeclarationRule' => [['rules.37']],
		'PHPStan\Rules\Classes\EnumSanityRule' => [['rules.38']],
		'PHPStan\Rules\Classes\InstantiationCallableRule' => [['rules.39']],
		'PHPStan\Rules\Classes\InvalidPromotedPropertiesRule' => [['rules.40']],
		'PHPStan\Rules\Classes\LocalTypeAliasesRule' => [['rules.41']],
		'PHPStan\Rules\Classes\LocalTypeTraitUseAliasesRule' => [['rules.42']],
		'PHPStan\Rules\Classes\LocalTypeTraitAliasesRule' => [['rules.43']],
		'PHPStan\Rules\Classes\NewStaticRule' => [['rules.44']],
		'PHPStan\Rules\Classes\NonClassAttributeClassRule' => [['rules.45']],
		'PHPStan\Rules\Classes\ReadOnlyClassRule' => [['rules.46']],
		'PHPStan\Rules\Classes\TraitAttributeClassRule' => [['rules.47']],
		'PHPStan\Rules\Constants\ClassAsClassConstantRule' => [['rules.48']],
		'PHPStan\Rules\Constants\DynamicClassConstantFetchRule' => [['rules.49']],
		'PHPStan\Rules\Constants\FinalConstantRule' => [['rules.50']],
		'PHPStan\Rules\Constants\MagicConstantContextRule' => [['rules.51']],
		'PHPStan\Rules\Constants\NativeTypedClassConstantRule' => [['rules.52']],
		'PHPStan\Rules\Constants\FinalPrivateConstantRule' => [['rules.53']],
		'PHPStan\Rules\EnumCases\EnumCaseAttributesRule' => [['rules.54']],
		'PHPStan\Rules\Exceptions\NoncapturingCatchRule' => [['rules.55']],
		'PHPStan\Rules\Exceptions\ThrowExpressionRule' => [['rules.56']],
		'PHPStan\Rules\Functions\ArrowFunctionAttributesRule' => [['rules.57']],
		'PHPStan\Rules\Functions\ArrowFunctionReturnNullsafeByRefRule' => [['rules.58']],
		'PHPStan\Rules\Functions\ClosureAttributesRule' => [['rules.59']],
		'PHPStan\Rules\Functions\DefineParametersRule' => [['rules.60']],
		'PHPStan\Rules\Functions\ExistingClassesInArrowFunctionTypehintsRule' => [['rules.61']],
		'PHPStan\Rules\Functions\CallToFunctionParametersRule' => [['rules.62']],
		'PHPStan\Rules\Functions\ExistingClassesInClosureTypehintsRule' => [['rules.63']],
		'PHPStan\Rules\Functions\ExistingClassesInTypehintsRule' => [['rules.64']],
		'PHPStan\Rules\Functions\FunctionAttributesRule' => [['rules.65']],
		'PHPStan\Rules\Functions\InnerFunctionRule' => [['rules.66']],
		'PHPStan\Rules\Functions\InvalidLexicalVariablesInClosureUseRule' => [['rules.67']],
		'PHPStan\Rules\Functions\ParamAttributesRule' => [['rules.68']],
		'PHPStan\Rules\Functions\PrintfArrayParametersRule' => [['rules.69']],
		'PHPStan\Rules\Functions\PrintfParametersRule' => [['rules.70']],
		'PHPStan\Rules\Functions\RedefinedParametersRule' => [['rules.71']],
		'PHPStan\Rules\Functions\ReturnNullsafeByRefRule' => [['rules.72']],
		'PHPStan\Rules\Ignore\IgnoreParseErrorRule' => [['rules.73']],
		'PHPStan\Rules\Functions\VariadicParametersDeclarationRule' => [['rules.74']],
		'PHPStan\Rules\Keywords\ContinueBreakInLoopRule' => [['rules.75']],
		'PHPStan\Rules\Keywords\DeclareStrictTypesRule' => [['rules.76']],
		'PHPStan\Rules\Methods\AbstractMethodInNonAbstractClassRule' => [['rules.77']],
		'PHPStan\Rules\Methods\AbstractPrivateMethodRule' => [['rules.78']],
		'PHPStan\Rules\Methods\CallMethodsRule' => [['rules.79']],
		'PHPStan\Rules\Methods\CallStaticMethodsRule' => [['rules.80']],
		'PHPStan\Rules\Methods\ConsistentConstructorRule' => [['rules.81']],
		'PHPStan\Rules\Methods\ConstructorReturnTypeRule' => [['rules.82']],
		'PHPStan\Rules\Methods\ExistingClassesInTypehintsRule' => [['rules.83']],
		'PHPStan\Rules\Methods\FinalPrivateMethodRule' => [['rules.84']],
		'PHPStan\Rules\Methods\MethodCallableRule' => [['rules.85']],
		'PHPStan\Rules\Methods\MethodVisibilityInInterfaceRule' => [['rules.86']],
		'PHPStan\Rules\Methods\MissingMagicSerializationMethodsRule' => [['rules.87']],
		'PHPStan\Rules\Methods\MissingMethodImplementationRule' => [['rules.88']],
		'PHPStan\Rules\Methods\MethodAttributesRule' => [['rules.89']],
		'PHPStan\Rules\Methods\StaticMethodCallableRule' => [['rules.90']],
		'PHPStan\Rules\Names\UsedNamesRule' => [['rules.91']],
		'PHPStan\Rules\Operators\InvalidAssignVarRule' => [['rules.92']],
		'PHPStan\Rules\Operators\InvalidIncDecOperationRule' => [['rules.93']],
		'PHPStan\Rules\Properties\AccessPropertiesInAssignRule' => [['rules.94']],
		'PHPStan\Rules\Properties\AccessStaticPropertiesInAssignRule' => [['rules.95']],
		'PHPStan\Rules\Properties\ExistingClassesInPropertyHookTypehintsRule' => [['rules.96']],
		'PHPStan\Rules\Properties\InvalidCallablePropertyTypeRule' => [['rules.97']],
		'PHPStan\Rules\Properties\MissingReadOnlyPropertyAssignRule' => [['rules.98']],
		'PHPStan\Rules\Properties\MissingReadOnlyByPhpDocPropertyAssignRule' => [['rules.99']],
		'PHPStan\Rules\Properties\PropertiesInInterfaceRule' => [['rules.100']],
		'PHPStan\Rules\Properties\PropertyAssignRefRule' => [['rules.101']],
		'PHPStan\Rules\Properties\PropertyAttributesRule' => [['rules.102']],
		'PHPStan\Rules\Properties\PropertyHookAttributesRule' => [['rules.103']],
		'PHPStan\Rules\Properties\PropertyInClassRule' => [['rules.104']],
		'PHPStan\Rules\Properties\ReadOnlyPropertyRule' => [['rules.105']],
		'PHPStan\Rules\Properties\ReadOnlyByPhpDocPropertyRule' => [['rules.106']],
		'PHPStan\Rules\Regexp\RegularExpressionPatternRule' => [['rules.107']],
		'PHPStan\Rules\Traits\ConflictingTraitConstantsRule' => [['rules.108']],
		'PHPStan\Rules\Traits\ConstantsInTraitsRule' => [['rules.109']],
		'PHPStan\Rules\Traits\TraitAttributesRule' => [['rules.110']],
		'PHPStan\Rules\Types\InvalidTypesInUnionRule' => [['rules.111']],
		'PHPStan\Rules\Variables\UnsetRule' => [['rules.112']],
		'PHPStan\Rules\Whitespace\FileWhitespaceRule' => [['rules.113']],
		'Composer\Pcre\PHPStan\UnsafeStrictGroupsCallRule' => [['rules.114']],
		'Composer\Pcre\PHPStan\InvalidRegexPatternRule' => [['rules.115']],
		'mglaman\PHPStanDrupal\Rules\Drupal\Coder\DiscouragedFunctionsRule' => [['rules.116']],
		'mglaman\PHPStanDrupal\Rules\Drupal\GlobalDrupalDependencyInjectionRule' => [['rules.117']],
		'mglaman\PHPStanDrupal\Rules\Drupal\PluginManager\AbstractPluginManagerRule' => [1 => ['rules.118']],
		'mglaman\PHPStanDrupal\Rules\Drupal\PluginManager\PluginManagerSetsCacheBackendRule' => [['rules.118']],
		'mglaman\PHPStanDrupal\Rules\Drupal\RenderCallbackRule' => [['rules.119']],
		'mglaman\PHPStanDrupal\Rules\Deprecations\StaticServiceDeprecatedServiceRule' => [['rules.120']],
		'mglaman\PHPStanDrupal\Rules\Deprecations\GetDeprecatedServiceRule' => [['rules.121']],
		'mglaman\PHPStanDrupal\Rules\Drupal\Tests\BrowserTestBaseDefaultThemeRule' => [['rules.122']],
		'mglaman\PHPStanDrupal\Rules\Deprecations\DeprecatedAnnotationsRuleBase' => [1 => ['rules.123', 'rules.124']],
		'mglaman\PHPStanDrupal\Rules\Deprecations\ConfigEntityConfigExportRule' => [['rules.123']],
		'mglaman\PHPStanDrupal\Rules\Deprecations\PluginAnnotationContextDefinitionsRule' => [['rules.124']],
		'mglaman\PHPStanDrupal\Rules\Drupal\LoadIncludeBase' => [1 => ['rules.125', 'rules.126']],
		'mglaman\PHPStanDrupal\Rules\Drupal\ModuleLoadInclude' => [['rules.125']],
		'mglaman\PHPStanDrupal\Rules\Drupal\LoadIncludes' => [['rules.126']],
		'mglaman\PHPStanDrupal\Rules\Drupal\EntityQuery\EntityQueryHasAccessCheckRule' => [['rules.127']],
		'mglaman\PHPStanDrupal\Rules\Drupal\TestClassesProtectedPropertyModulesRule' => [['rules.128']],
		'PHPStan\Rules\Deprecations\FetchingDeprecatedConstRule' => [['rules.129']],
		'PHPStan\Rules\PHPUnit\AssertSameBooleanExpectedRule' => [['rules.130']],
		'PHPStan\Rules\PHPUnit\AssertSameNullExpectedRule' => [['rules.131']],
		'PHPStan\Rules\PHPUnit\AssertSameWithCountRule' => [['rules.132']],
		'PHPStan\Rules\PHPUnit\ClassCoversExistsRule' => [['rules.133']],
		'PHPStan\Rules\PHPUnit\ClassMethodCoversExistsRule' => [['rules.134']],
		'PHPStan\Rules\PHPUnit\MockMethodCallRule' => [['rules.135']],
		'PHPStan\Rules\PHPUnit\NoMissingSpaceInClassAnnotationRule' => [['rules.136']],
		'PHPStan\Rules\PHPUnit\NoMissingSpaceInMethodAnnotationRule' => [['rules.137']],
		'PHPStan\Rules\PHPUnit\ShouldCallParentMethodsRule' => [['rules.138']],
		'PhpParser\BuilderFactory' => [['01']],
		'PHPStan\Parser\LexerFactory' => [['02']],
		'PhpParser\NodeVisitorAbstract' => [
			[
				'03',
				'04',
				'05',
				'06',
				'07',
				'08',
				'09',
				'010',
				'011',
				'012',
				'013',
				'014',
				'015',
				'016',
				'017',
				'018',
				'019',
				'020',
				'021',
				'022',
				'074',
				'089',
				'090',
				'099',
			],
		],
		'PhpParser\NodeVisitor' => [
			[
				'03',
				'04',
				'05',
				'06',
				'07',
				'08',
				'09',
				'010',
				'011',
				'012',
				'013',
				'014',
				'015',
				'016',
				'017',
				'018',
				'019',
				'020',
				'021',
				'022',
				'074',
				'089',
				'090',
				'099',
			],
		],
		'PhpParser\NodeVisitor\NameResolver' => [['03']],
		'PHPStan\Parser\AnonymousClassVisitor' => [['04']],
		'PHPStan\Parser\ArrayFilterArgVisitor' => [['05']],
		'PHPStan\Parser\ArrayFindArgVisitor' => [['06']],
		'PHPStan\Parser\ArrayMapArgVisitor' => [['07']],
		'PHPStan\Parser\ArrayWalkArgVisitor' => [['08']],
		'PHPStan\Parser\ClosureArgVisitor' => [['09']],
		'PHPStan\Parser\ClosureBindToVarVisitor' => [['010']],
		'PHPStan\Parser\ClosureBindArgVisitor' => [['011']],
		'PHPStan\Parser\CurlSetOptArgVisitor' => [['012']],
		'PHPStan\Parser\ArrowFunctionArgVisitor' => [['013']],
		'PHPStan\Parser\MagicConstantParamDefaultVisitor' => [['014']],
		'PHPStan\Parser\NewAssignedToPropertyVisitor' => [['015']],
		'PHPStan\Parser\ParentStmtTypesVisitor' => [['016']],
		'PHPStan\Parser\StandaloneThrowExprVisitor' => [['017']],
		'PHPStan\Parser\TryCatchTypeVisitor' => [['018']],
		'PHPStan\Parser\LastConditionVisitor' => [['019']],
		'PHPStan\Parser\TypeTraverserInstanceofVisitor' => [['020']],
		'PHPStan\Parser\VariadicMethodsVisitor' => [['021']],
		'PHPStan\Parser\VariadicFunctionsVisitor' => [['022']],
		'PHPStan\Node\Printer\ExprPrinter' => [['023']],
		'PhpParser\PrettyPrinter\Standard' => [1 => ['024']],
		'PhpParser\PrettyPrinterAbstract' => [1 => ['024']],
		'PhpParser\PrettyPrinter' => [1 => ['024']],
		'PHPStan\Node\Printer\Printer' => [['024']],
		'PHPStan\Broker\AnonymousClassNameHelper' => [['025']],
		'PHPStan\Php\PhpVersion' => [['026']],
		'PHPStan\Php\PhpVersionFactory' => [['027']],
		'PHPStan\Php\PhpVersionFactoryFactory' => [['028']],
		'PHPStan\Php\ComposerPhpVersionFactory' => [['029']],
		'PHPStan\PhpDocParser\ParserConfig' => [['030']],
		'PHPStan\PhpDocParser\Lexer\Lexer' => [['031']],
		'PHPStan\PhpDocParser\Parser\TypeParser' => [['032']],
		'PHPStan\PhpDocParser\Parser\ConstExprParser' => [['033']],
		'PHPStan\PhpDocParser\Parser\PhpDocParser' => [['034']],
		'PHPStan\PhpDocParser\Printer\Printer' => [['035']],
		'PHPStan\PhpDoc\PhpDocInheritanceResolver' => [['036']],
		'PHPStan\PhpDoc\PhpDocNodeResolver' => [['037']],
		'PHPStan\PhpDoc\PhpDocStringResolver' => [['038']],
		'PHPStan\PhpDoc\ConstExprNodeResolver' => [['039']],
		'PHPStan\PhpDoc\TypeNodeResolver' => [['040']],
		'PHPStan\PhpDoc\TypeNodeResolverExtensionRegistryProvider' => [['041']],
		'PHPStan\PhpDoc\TypeStringResolver' => [['042']],
		'PHPStan\PhpDoc\StubValidator' => [['043']],
		'PHPStan\PhpDoc\StubFilesExtension' => [['044', '046', '047', '048', '0421']],
		'PHPStan\PhpDoc\SocketSelectStubFilesExtension' => [['044']],
		'PHPStan\PhpDoc\StubFilesProvider' => [['045']],
		'PHPStan\PhpDoc\DefaultStubFilesProvider' => [['045']],
		'PHPStan\PhpDoc\JsonValidateStubFilesExtension' => [['046']],
		'PHPStan\PhpDoc\ReflectionClassStubFilesExtension' => [['047']],
		'PHPStan\PhpDoc\ReflectionEnumStubFilesExtension' => [['048']],
		'PHPStan\Analyser\Analyser' => [['049']],
		'PHPStan\Analyser\AnalyserResultFinalizer' => [['050']],
		'PHPStan\Analyser\FileAnalyser' => [['051']],
		'PHPStan\Analyser\IgnoreErrorExtensionProvider' => [['052']],
		'PHPStan\Analyser\LocalIgnoresProcessor' => [['053']],
		'PHPStan\Analyser\RuleErrorTransformer' => [['054']],
		'PHPStan\Analyser\Ignore\IgnoredErrorHelper' => [['055']],
		'PHPStan\Analyser\Ignore\IgnoreLexer' => [['056']],
		'PHPStan\Analyser\InternalScopeFactory' => [['057']],
		'PHPStan\Analyser\LazyInternalScopeFactory' => [['057']],
		'PHPStan\Analyser\ScopeFactory' => [['058']],
		'PHPStan\Analyser\NodeScopeResolver' => [['059']],
		'PHPStan\Analyser\ConstantResolver' => [['060']],
		'PHPStan\Analyser\ConstantResolverFactory' => [['061']],
		'PHPStan\Analyser\ResultCache\ResultCacheManagerFactory' => [['062']],
		'PHPStan\Analyser\ResultCache\ResultCacheClearer' => [['063']],
		'PHPStan\Analyser\RicherScopeGetTypeHelper' => [['064']],
		'PHPStan\Cache\Cache' => [['065']],
		'PHPStan\Collectors\Registry' => [['066']],
		'PHPStan\Collectors\RegistryFactory' => [['067']],
		'PHPStan\Command\AnalyseApplication' => [['068']],
		'PHPStan\Command\AnalyserRunner' => [['069']],
		'PHPStan\Command\FixerApplication' => [['070']],
		'PHPStan\Dependency\DependencyResolver' => [['071']],
		'PHPStan\Dependency\ExportedNodeFetcher' => [['072']],
		'PHPStan\Dependency\ExportedNodeResolver' => [['073']],
		'PHPStan\Dependency\ExportedNodeVisitor' => [['074']],
		'PHPStan\DependencyInjection\Container' => [['075'], ['076']],
		'PHPStan\DependencyInjection\Nette\NetteContainer' => [['076']],
		'PHPStan\DependencyInjection\DerivativeContainerFactory' => [['077']],
		'PHPStan\DependencyInjection\Reflection\ClassReflectionExtensionRegistryProvider' => [['078']],
		'PHPStan\DependencyInjection\Type\DynamicReturnTypeExtensionRegistryProvider' => [['079']],
		'PHPStan\DependencyInjection\Type\ParameterOutTypeExtensionProvider' => [['080']],
		'PHPStan\DependencyInjection\Type\ExpressionTypeResolverExtensionRegistryProvider' => [['081']],
		'PHPStan\DependencyInjection\Type\OperatorTypeSpecifyingExtensionRegistryProvider' => [['082']],
		'PHPStan\DependencyInjection\Type\DynamicThrowTypeExtensionProvider' => [['083']],
		'PHPStan\DependencyInjection\Type\ParameterClosureTypeExtensionProvider' => [['084']],
		'PHPStan\File\FileHelper' => [['085']],
		'PHPStan\File\FileExcluderFactory' => [['086']],
		'PHPStan\File\FileExcluderRawFactory' => [['087']],
		'PHPStan\File\FileExcluder' => [2 => ['fileExcluderAnalyse', 'fileExcluderScan']],
		'PHPStan\File\FileFinder' => [2 => ['fileFinderAnalyse', 'fileFinderScan']],
		'PHPStan\File\FileMonitor' => [['088']],
		'PHPStan\Parser\DeclarePositionVisitor' => [['089']],
		'PHPStan\Parser\ImmediatelyInvokedClosureVisitor' => [['090']],
		'PHPStan\Parallel\ParallelAnalyser' => [['091']],
		'PHPStan\Diagnose\DiagnoseExtension' => [0 => ['092'], 2 => [1 => 'phpstanDiagnoseExtension']],
		'PHPStan\Parallel\Scheduler' => [['092']],
		'PHPStan\Process\CpuCoreCounter' => [['093']],
		'PHPStan\Reflection\AttributeReflectionFactory' => [['094']],
		'PHPStan\Reflection\FunctionReflectionFactory' => [['095']],
		'PHPStan\Reflection\InitializerExprTypeResolver' => [['096']],
		'PHPStan\Reflection\MethodsClassReflectionExtension' => [['097', '0111', '0113', '0115', '0117', '0420']],
		'PHPStan\Reflection\Annotations\AnnotationsMethodsClassReflectionExtension' => [['097']],
		'PHPStan\Reflection\PropertiesClassReflectionExtension' => [
			['098', '0112', '0114', '0115', '0119', '0286', '0419'],
		],
		'PHPStan\Reflection\Annotations\AnnotationsPropertiesClassReflectionExtension' => [['098']],
		'PHPStan\Reflection\BetterReflection\SourceLocator\CachingVisitor' => [['099']],
		'PHPStan\Reflection\BetterReflection\SourceLocator\FileNodesFetcher' => [['0100']],
		'PHPStan\Reflection\BetterReflection\SourceLocator\ComposerJsonAndInstalledJsonSourceLocatorMaker' => [['0101']],
		'PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedDirectorySourceLocatorFactory' => [['0102']],
		'PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedDirectorySourceLocatorRepository' => [['0103']],
		'PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedPsrAutoloaderLocatorFactory' => [['0104']],
		'PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedSingleFileSourceLocatorFactory' => [['0105']],
		'PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedSingleFileSourceLocatorRepository' => [['0106']],
		'PHPStan\Type\DynamicMethodReturnTypeExtension' => [
			[
				'0107',
				'0108',
				'0109',
				'0120',
				'0121',
				'0230',
				'0241',
				'0247',
				'0248',
				'0253',
				'0288',
				'0316',
				'0343',
				'0344',
				'0351',
				'0352',
				'0353',
				'0354',
				'0355',
				'0356',
				'0358',
				'0399',
				'0400',
				'0407',
				'0408',
				'0409',
				'0410',
				'0411',
				'0412',
				'0413',
				'0414',
				'0415',
				'0445',
			],
		],
		'PHPStan\Reflection\BetterReflection\Type\AdapterReflectionEnumCaseDynamicReturnTypeExtension' => [
			['0107', '0108'],
		],
		'PHPStan\Reflection\BetterReflection\Type\AdapterReflectionEnumDynamicReturnTypeExtension' => [['0109']],
		'PHPStan\Reflection\ConstructorsHelper' => [['0110']],
		'PHPStan\Reflection\RequireExtension\RequireExtendsMethodsClassReflectionExtension' => [['0111']],
		'PHPStan\Reflection\RequireExtension\RequireExtendsPropertiesClassReflectionExtension' => [['0112']],
		'PHPStan\Reflection\Mixin\MixinMethodsClassReflectionExtension' => [['0113']],
		'PHPStan\Reflection\Mixin\MixinPropertiesClassReflectionExtension' => [['0114']],
		'PHPStan\Reflection\Php\PhpClassReflectionExtension' => [['0115']],
		'PHPStan\Reflection\Php\PhpMethodReflectionFactory' => [['0116']],
		'PHPStan\Reflection\Php\Soap\SoapClientMethodsClassReflectionExtension' => [['0117']],
		'PHPStan\Reflection\AllowedSubTypesClassReflectionExtension' => [['0118']],
		'PHPStan\Reflection\Php\EnumAllowedSubTypesClassReflectionExtension' => [['0118']],
		'PHPStan\Reflection\Php\UniversalObjectCratesClassReflectionExtension' => [['0119']],
		'PHPStan\Reflection\PHPStan\NativeReflectionEnumReturnDynamicReturnTypeExtension' => [['0120', '0121']],
		'PHPStan\Reflection\ReflectionProvider\ReflectionProviderProvider' => [['0122']],
		'PHPStan\Reflection\SignatureMap\NativeFunctionReflectionProvider' => [['0123']],
		'PHPStan\Reflection\SignatureMap\SignatureMapParser' => [['0124']],
		'PHPStan\Reflection\SignatureMap\SignatureMapProvider' => [['0128'], ['0125', '0126']],
		'PHPStan\Reflection\SignatureMap\FunctionSignatureMapProvider' => [['0125']],
		'PHPStan\Reflection\SignatureMap\Php8SignatureMapProvider' => [['0126']],
		'PHPStan\Reflection\SignatureMap\SignatureMapProviderFactory' => [['0127']],
		'PHPStan\Rules\Api\ApiRuleHelper' => [['0129']],
		'PHPStan\Rules\AttributesCheck' => [['0130']],
		'PHPStan\Rules\Arrays\NonexistentOffsetInArrayDimFetchCheck' => [['0131']],
		'PHPStan\Rules\ClassNameCheck' => [['0132']],
		'PHPStan\Rules\ClassCaseSensitivityCheck' => [['0133']],
		'PHPStan\Rules\ClassForbiddenNameCheck' => [['0134']],
		'PHPStan\Rules\Classes\LocalTypeAliasesCheck' => [['0135']],
		'PHPStan\Rules\Classes\MethodTagCheck' => [['0136']],
		'PHPStan\Rules\Classes\MixinCheck' => [['0137']],
		'PHPStan\Rules\Classes\PropertyTagCheck' => [['0138']],
		'PHPStan\Rules\Comparison\ConstantConditionRuleHelper' => [['0139']],
		'PHPStan\Rules\Comparison\ImpossibleCheckTypeHelper' => [['0140']],
		'PHPStan\Rules\Exceptions\ExceptionTypeResolver' => [1 => ['0141'], [1 => 'exceptionTypeResolver']],
		'PHPStan\Rules\Exceptions\DefaultExceptionTypeResolver' => [['0141']],
		'PHPStan\Rules\Exceptions\MissingCheckedExceptionInFunctionThrowsRule' => [['0142']],
		'PHPStan\Rules\Exceptions\MissingCheckedExceptionInMethodThrowsRule' => [['0143']],
		'PHPStan\Rules\Exceptions\MissingCheckedExceptionInPropertyHookThrowsRule' => [['0144']],
		'PHPStan\Rules\Exceptions\MissingCheckedExceptionInThrowsCheck' => [['0145']],
		'PHPStan\Rules\Exceptions\TooWideThrowTypeCheck' => [['0146']],
		'PHPStan\Rules\FunctionCallParametersCheck' => [['0147']],
		'PHPStan\Rules\FunctionDefinitionCheck' => [['0148']],
		'PHPStan\Rules\FunctionReturnTypeCheck' => [['0149']],
		'PHPStan\Rules\ParameterCastableToStringCheck' => [['0150']],
		'PHPStan\Rules\Generics\CrossCheckInterfacesHelper' => [['0151']],
		'PHPStan\Rules\Generics\GenericAncestorsCheck' => [['0152']],
		'PHPStan\Rules\Generics\GenericObjectTypeCheck' => [['0153']],
		'PHPStan\Rules\Generics\MethodTagTemplateTypeCheck' => [['0154']],
		'PHPStan\Rules\Generics\TemplateTypeCheck' => [['0155']],
		'PHPStan\Rules\Generics\VarianceCheck' => [['0156']],
		'PHPStan\Rules\InternalTag\RestrictedInternalUsageHelper' => [['0157']],
		'PHPStan\Rules\IssetCheck' => [['0158']],
		'PHPStan\Rules\Methods\MethodCallCheck' => [['0159']],
		'PHPStan\Rules\Methods\StaticMethodCallCheck' => [['0160']],
		'PHPStan\Rules\Methods\MethodSignatureRule' => [['0161']],
		'PHPStan\Rules\Methods\MethodParameterComparisonHelper' => [['0162']],
		'PHPStan\Rules\Methods\MethodVisibilityComparisonHelper' => [['0163']],
		'PHPStan\Rules\MissingTypehintCheck' => [['0164']],
		'PHPStan\Rules\NullsafeCheck' => [['0165']],
		'PHPStan\Rules\Constants\AlwaysUsedClassConstantsExtensionProvider' => [['0166']],
		'PHPStan\Rules\Constants\LazyAlwaysUsedClassConstantsExtensionProvider' => [['0166']],
		'PHPStan\Rules\Methods\AlwaysUsedMethodExtensionProvider' => [['0167']],
		'PHPStan\Rules\Methods\LazyAlwaysUsedMethodExtensionProvider' => [['0167']],
		'PHPStan\Rules\PhpDoc\ConditionalReturnTypeRuleHelper' => [['0168']],
		'PHPStan\Rules\PhpDoc\AssertRuleHelper' => [['0169']],
		'PHPStan\Rules\PhpDoc\UnresolvableTypeHelper' => [['0170']],
		'PHPStan\Rules\PhpDoc\GenericCallableRuleHelper' => [['0171']],
		'PHPStan\Rules\PhpDoc\IncompatiblePhpDocTypeCheck' => [['0172']],
		'PHPStan\Rules\PhpDoc\VarTagTypeRuleHelper' => [['0173']],
		'PHPStan\Rules\Playground\NeverRuleHelper' => [['0174']],
		'PHPStan\Rules\Properties\AccessPropertiesCheck' => [['0175']],
		'PHPStan\Type\OperatorTypeSpecifyingExtension' => [['0176']],
		'PHPStan\Type\Php\BcMathNumberOperatorTypeSpecifyingExtension' => [['0176']],
		'PHPStan\Rules\Properties\UninitializedPropertyRule' => [['0177']],
		'PHPStan\Rules\Properties\ReadWritePropertiesExtensionProvider' => [['0178']],
		'PHPStan\Rules\Properties\LazyReadWritePropertiesExtensionProvider' => [['0178']],
		'PHPStan\Rules\Properties\PropertyDescriptor' => [['0179']],
		'PHPStan\Rules\Properties\PropertyReflectionFinder' => [['0180']],
		'PHPStan\Rules\Pure\FunctionPurityCheck' => [['0181']],
		'PHPStan\Rules\RuleLevelHelper' => [['0182']],
		'PHPStan\Rules\UnusedFunctionParametersCheck' => [['0183']],
		'PHPStan\Rules\TooWideTypehints\TooWideParameterOutTypeCheck' => [['0184']],
		'PHPStan\Type\FileTypeMapper' => [0 => ['0185'], 2 => [1 => 'stubFileTypeMapper']],
		'PHPStan\Type\TypeAliasResolver' => [['0186']],
		'PHPStan\Type\TypeAliasResolverProvider' => [['0187']],
		'PHPStan\Type\BitwiseFlagHelper' => [['0188']],
		'PHPStan\Type\DynamicFunctionReturnTypeExtension' => [
			[
				'0189',
				'0190',
				'0191',
				'0192',
				'0193',
				'0195',
				'0196',
				'0197',
				'0198',
				'0199',
				'0201',
				'0202',
				'0203',
				'0204',
				'0205',
				'0207',
				'0208',
				'0209',
				'0210',
				'0211',
				'0212',
				'0213',
				'0214',
				'0215',
				'0216',
				'0217',
				'0218',
				'0219',
				'0220',
				'0221',
				'0223',
				'0224',
				'0227',
				'0228',
				'0232',
				'0233',
				'0235',
				'0236',
				'0238',
				'0240',
				'0242',
				'0245',
				'0246',
				'0255',
				'0256',
				'0258',
				'0259',
				'0260',
				'0261',
				'0262',
				'0263',
				'0264',
				'0265',
				'0266',
				'0267',
				'0268',
				'0269',
				'0271',
				'0288',
				'0291',
				'0292',
				'0293',
				'0294',
				'0295',
				'0297',
				'0298',
				'0299',
				'0300',
				'0301',
				'0302',
				'0303',
				'0304',
				'0305',
				'0306',
				'0307',
				'0309',
				'0310',
				'0311',
				'0312',
				'0313',
				'0314',
				'0315',
				'0317',
				'0318',
				'0319',
				'0320',
				'0321',
				'0322',
				'0323',
				'0324',
				'0325',
				'0328',
				'0337',
				'0341',
				'0342',
				'0345',
				'0346',
				'0347',
				'0348',
				'0349',
				'0350',
			],
		],
		'PHPStan\Type\Php\AbsFunctionDynamicReturnTypeExtension' => [['0189']],
		'PHPStan\Type\Php\ArgumentBasedFunctionReturnTypeExtension' => [['0190']],
		'PHPStan\Type\Php\ArrayChangeKeyCaseFunctionReturnTypeExtension' => [['0191']],
		'PHPStan\Type\Php\ArrayIntersectKeyFunctionReturnTypeExtension' => [['0192']],
		'PHPStan\Type\Php\ArrayChunkFunctionReturnTypeExtension' => [['0193']],
		'PHPStan\Type\Php\ArrayColumnHelper' => [['0194']],
		'PHPStan\Type\Php\ArrayColumnFunctionReturnTypeExtension' => [['0195']],
		'PHPStan\Type\Php\ArrayCombineFunctionReturnTypeExtension' => [['0196']],
		'PHPStan\Type\Php\ArrayCurrentDynamicReturnTypeExtension' => [['0197']],
		'PHPStan\Type\Php\ArrayFillFunctionReturnTypeExtension' => [['0198']],
		'PHPStan\Type\Php\ArrayFillKeysFunctionReturnTypeExtension' => [['0199']],
		'PHPStan\Type\Php\ArrayFilterFunctionReturnTypeHelper' => [['0200']],
		'PHPStan\Type\Php\ArrayFilterFunctionReturnTypeExtension' => [['0201']],
		'PHPStan\Type\Php\ArrayFlipFunctionReturnTypeExtension' => [['0202']],
		'PHPStan\Type\Php\ArrayFindFunctionReturnTypeExtension' => [['0203']],
		'PHPStan\Type\Php\ArrayFindKeyFunctionReturnTypeExtension' => [['0204']],
		'PHPStan\Type\Php\ArrayKeyDynamicReturnTypeExtension' => [['0205']],
		'PHPStan\Type\FunctionTypeSpecifyingExtension' => [
			[
				'0206',
				'0222',
				'0237',
				'0275',
				'0285',
				'0289',
				'0290',
				'0308',
				'0326',
				'0327',
				'0329',
				'0330',
				'0331',
				'0332',
				'0333',
				'0334',
				'0335',
				'0336',
				'0338',
				'0340',
				'0442',
			],
		],
		'PHPStan\Analyser\TypeSpecifierAwareExtension' => [
			[
				'0206',
				'0222',
				'0237',
				'0275',
				'0285',
				'0289',
				'0290',
				'0296',
				'0308',
				'0326',
				'0327',
				'0329',
				'0330',
				'0331',
				'0332',
				'0333',
				'0334',
				'0335',
				'0336',
				'0338',
				'0340',
				'0342',
				'0402',
				'0422',
				'0426',
				'0442',
				'0443',
				'0444',
			],
		],
		'PHPStan\Type\Php\ArrayKeyExistsFunctionTypeSpecifyingExtension' => [['0206']],
		'PHPStan\Type\Php\ArrayKeyFirstDynamicReturnTypeExtension' => [['0207']],
		'PHPStan\Type\Php\ArrayKeyLastDynamicReturnTypeExtension' => [['0208']],
		'PHPStan\Type\Php\ArrayKeysFunctionDynamicReturnTypeExtension' => [['0209']],
		'PHPStan\Type\Php\ArrayMapFunctionReturnTypeExtension' => [['0210']],
		'PHPStan\Type\Php\ArrayMergeFunctionDynamicReturnTypeExtension' => [['0211']],
		'PHPStan\Type\Php\ArrayNextDynamicReturnTypeExtension' => [['0212']],
		'PHPStan\Type\Php\ArrayPopFunctionReturnTypeExtension' => [['0213']],
		'PHPStan\Type\Php\ArrayRandFunctionReturnTypeExtension' => [['0214']],
		'PHPStan\Type\Php\ArrayReduceFunctionReturnTypeExtension' => [['0215']],
		'PHPStan\Type\Php\ArrayReplaceFunctionReturnTypeExtension' => [['0216']],
		'PHPStan\Type\Php\ArrayReverseFunctionReturnTypeExtension' => [['0217']],
		'PHPStan\Type\Php\ArrayShiftFunctionReturnTypeExtension' => [['0218']],
		'PHPStan\Type\Php\ArraySliceFunctionReturnTypeExtension' => [['0219']],
		'PHPStan\Type\Php\ArraySpliceFunctionReturnTypeExtension' => [['0220']],
		'PHPStan\Type\Php\ArraySearchFunctionDynamicReturnTypeExtension' => [['0221']],
		'PHPStan\Type\Php\ArraySearchFunctionTypeSpecifyingExtension' => [['0222']],
		'PHPStan\Type\Php\ArrayValuesFunctionDynamicReturnTypeExtension' => [['0223']],
		'PHPStan\Type\Php\ArraySumFunctionDynamicReturnTypeExtension' => [['0224']],
		'PHPStan\Type\DynamicFunctionThrowTypeExtension' => [['0225', '0270', '0272']],
		'PHPStan\Type\Php\AssertThrowTypeExtension' => [['0225']],
		'PHPStan\Type\DynamicStaticMethodReturnTypeExtension' => [
			['0226', '0229', '0231', '0244', '0351', '0357', '0416', '0417', '0418'],
		],
		'PHPStan\Type\Php\BackedEnumFromMethodDynamicReturnTypeExtension' => [['0226']],
		'PHPStan\Type\Php\Base64DecodeDynamicFunctionReturnTypeExtension' => [['0227']],
		'PHPStan\Type\Php\BcMathStringOrNullReturnTypeExtension' => [['0228']],
		'PHPStan\Type\Php\ClosureBindDynamicReturnTypeExtension' => [['0229']],
		'PHPStan\Type\Php\ClosureBindToDynamicReturnTypeExtension' => [['0230']],
		'PHPStan\Type\Php\ClosureFromCallableDynamicReturnTypeExtension' => [['0231']],
		'PHPStan\Type\Php\CompactFunctionReturnTypeExtension' => [['0232']],
		'PHPStan\Type\Php\ConstantFunctionReturnTypeExtension' => [['0233']],
		'PHPStan\Type\Php\ConstantHelper' => [['0234']],
		'PHPStan\Type\Php\CountFunctionReturnTypeExtension' => [['0235']],
		'PHPStan\Type\Php\CountCharsFunctionDynamicReturnTypeExtension' => [['0236']],
		'PHPStan\Type\Php\CountFunctionTypeSpecifyingExtension' => [['0237']],
		'PHPStan\Type\Php\CurlGetinfoFunctionDynamicReturnTypeExtension' => [['0238']],
		'PHPStan\Type\Php\DateFunctionReturnTypeHelper' => [['0239']],
		'PHPStan\Type\Php\DateFormatFunctionReturnTypeExtension' => [['0240']],
		'PHPStan\Type\Php\DateFormatMethodReturnTypeExtension' => [['0241']],
		'PHPStan\Type\Php\DateFunctionReturnTypeExtension' => [['0242']],
		'PHPStan\Type\DynamicStaticMethodThrowTypeExtension' => [
			['0243', '0249', '0252', '0281', '0282', '0283', '0284', '0287'],
		],
		'PHPStan\Type\Php\DateIntervalConstructorThrowTypeExtension' => [['0243']],
		'PHPStan\Type\Php\DateIntervalDynamicReturnTypeExtension' => [['0244']],
		'PHPStan\Type\Php\DateTimeCreateDynamicReturnTypeExtension' => [['0245']],
		'PHPStan\Type\Php\DateTimeDynamicReturnTypeExtension' => [['0246']],
		'PHPStan\Type\Php\DateTimeModifyReturnTypeExtension' => [['0247', '0248']],
		'PHPStan\Type\Php\DateTimeConstructorThrowTypeExtension' => [['0249']],
		'PHPStan\Type\DynamicMethodThrowTypeExtension' => [['0250', '0251', '0254']],
		'PHPStan\Type\Php\DateTimeModifyMethodThrowTypeExtension' => [['0250']],
		'PHPStan\Type\Php\DateTimeSubMethodThrowTypeExtension' => [['0251']],
		'PHPStan\Type\Php\DateTimeZoneConstructorThrowTypeExtension' => [['0252']],
		'PHPStan\Type\Php\DsMapDynamicReturnTypeExtension' => [['0253']],
		'PHPStan\Type\Php\DsMapDynamicMethodThrowTypeExtension' => [['0254']],
		'PHPStan\Type\Php\DioStatDynamicFunctionReturnTypeExtension' => [['0255']],
		'PHPStan\Type\Php\ExplodeFunctionDynamicReturnTypeExtension' => [['0256']],
		'PHPStan\Type\Php\FilterFunctionReturnTypeHelper' => [['0257']],
		'PHPStan\Type\Php\FilterInputDynamicReturnTypeExtension' => [['0258']],
		'PHPStan\Type\Php\FilterVarDynamicReturnTypeExtension' => [['0259']],
		'PHPStan\Type\Php\FilterVarArrayDynamicReturnTypeExtension' => [['0260']],
		'PHPStan\Type\Php\GetCalledClassDynamicReturnTypeExtension' => [['0261']],
		'PHPStan\Type\Php\GetClassDynamicReturnTypeExtension' => [['0262']],
		'PHPStan\Type\Php\GetDebugTypeFunctionReturnTypeExtension' => [['0263']],
		'PHPStan\Type\Php\GetDefinedVarsFunctionReturnTypeExtension' => [['0264']],
		'PHPStan\Type\Php\GetParentClassDynamicFunctionReturnTypeExtension' => [['0265']],
		'PHPStan\Type\Php\GettypeFunctionReturnTypeExtension' => [['0266']],
		'PHPStan\Type\Php\GettimeofdayDynamicFunctionReturnTypeExtension' => [['0267']],
		'PHPStan\Type\Php\HashFunctionsReturnTypeExtension' => [['0268']],
		'PHPStan\Type\Php\HighlightStringDynamicReturnTypeExtension' => [['0269']],
		'PHPStan\Type\Php\IntdivThrowTypeExtension' => [['0270']],
		'PHPStan\Type\Php\IniGetReturnTypeExtension' => [['0271']],
		'PHPStan\Type\Php\JsonThrowTypeExtension' => [['0272']],
		'PHPStan\Type\FunctionParameterOutTypeExtension' => [['0273', '0274', '0276']],
		'PHPStan\Type\Php\OpenSslEncryptParameterOutTypeExtension' => [['0273']],
		'PHPStan\Type\Php\ParseStrParameterOutTypeExtension' => [['0274']],
		'PHPStan\Type\Php\PregMatchTypeSpecifyingExtension' => [['0275']],
		'PHPStan\Type\Php\PregMatchParameterOutTypeExtension' => [['0276']],
		'PHPStan\Type\FunctionParameterClosureTypeExtension' => [['0277']],
		'PHPStan\Type\Php\PregReplaceCallbackClosureTypeExtension' => [['0277']],
		'PHPStan\Type\Php\RegexArrayShapeMatcher' => [['0278']],
		'PHPStan\Type\Regex\RegexGroupParser' => [['0279']],
		'PHPStan\Type\Regex\RegexExpressionHelper' => [['0280']],
		'PHPStan\Type\Php\ReflectionClassConstructorThrowTypeExtension' => [['0281']],
		'PHPStan\Type\Php\ReflectionFunctionConstructorThrowTypeExtension' => [['0282']],
		'PHPStan\Type\Php\ReflectionMethodConstructorThrowTypeExtension' => [['0283']],
		'PHPStan\Type\Php\ReflectionPropertyConstructorThrowTypeExtension' => [['0284']],
		'PHPStan\Type\Php\StrContainingTypeSpecifyingExtension' => [['0285']],
		'PHPStan\Type\Php\SimpleXMLElementClassPropertyReflectionExtension' => [['0286']],
		'PHPStan\Type\Php\SimpleXMLElementConstructorThrowTypeExtension' => [['0287']],
		'PHPStan\Type\Php\StatDynamicReturnTypeExtension' => [['0288']],
		'PHPStan\Type\Php\MethodExistsTypeSpecifyingExtension' => [['0289']],
		'PHPStan\Type\Php\PropertyExistsTypeSpecifyingExtension' => [['0290']],
		'PHPStan\Type\Php\MinMaxFunctionReturnTypeExtension' => [['0291']],
		'PHPStan\Type\Php\NumberFormatFunctionDynamicReturnTypeExtension' => [['0292']],
		'PHPStan\Type\Php\PathinfoFunctionDynamicReturnTypeExtension' => [['0293']],
		'PHPStan\Type\Php\PregFilterFunctionReturnTypeExtension' => [['0294']],
		'PHPStan\Type\Php\PregSplitDynamicReturnTypeExtension' => [['0295']],
		'PHPStan\Type\MethodTypeSpecifyingExtension' => [['0296', '0422', '0443']],
		'PHPStan\Type\Php\ReflectionClassIsSubclassOfTypeSpecifyingExtension' => [['0296']],
		'PHPStan\Type\Php\ReplaceFunctionsDynamicReturnTypeExtension' => [['0297']],
		'PHPStan\Type\Php\ArrayPointerFunctionsDynamicReturnTypeExtension' => [['0298']],
		'PHPStan\Type\Php\LtrimFunctionReturnTypeExtension' => [['0299']],
		'PHPStan\Type\Php\MbFunctionsReturnTypeExtension' => [['0300']],
		'PHPStan\Type\Php\MbConvertEncodingFunctionReturnTypeExtension' => [['0301']],
		'PHPStan\Type\Php\MbSubstituteCharacterDynamicReturnTypeExtension' => [['0302']],
		'PHPStan\Type\Php\MbStrlenFunctionReturnTypeExtension' => [['0303']],
		'PHPStan\Type\Php\MicrotimeFunctionReturnTypeExtension' => [['0304']],
		'PHPStan\Type\Php\HrtimeFunctionReturnTypeExtension' => [['0305']],
		'PHPStan\Type\Php\ImplodeFunctionReturnTypeExtension' => [['0306']],
		'PHPStan\Type\Php\NonEmptyStringFunctionsReturnTypeExtension' => [['0307']],
		'PHPStan\Type\Php\SetTypeFunctionTypeSpecifyingExtension' => [['0308']],
		'PHPStan\Type\Php\StrCaseFunctionsReturnTypeExtension' => [['0309']],
		'PHPStan\Type\Php\StrlenFunctionReturnTypeExtension' => [['0310']],
		'PHPStan\Type\Php\StrIncrementDecrementFunctionReturnTypeExtension' => [['0311']],
		'PHPStan\Type\Php\StrPadFunctionReturnTypeExtension' => [['0312']],
		'PHPStan\Type\Php\StrRepeatFunctionReturnTypeExtension' => [['0313']],
		'PHPStan\Type\Php\StrrevFunctionReturnTypeExtension' => [['0314']],
		'PHPStan\Type\Php\SubstrDynamicReturnTypeExtension' => [['0315']],
		'PHPStan\Type\Php\ThrowableReturnTypeExtension' => [['0316']],
		'PHPStan\Type\Php\ParseUrlFunctionDynamicReturnTypeExtension' => [['0317']],
		'PHPStan\Type\Php\TriggerErrorDynamicReturnTypeExtension' => [['0318']],
		'PHPStan\Type\Php\TrimFunctionDynamicReturnTypeExtension' => [['0319']],
		'PHPStan\Type\Php\VersionCompareFunctionDynamicReturnTypeExtension' => [['0320']],
		'PHPStan\Type\Php\PowFunctionReturnTypeExtension' => [['0321']],
		'PHPStan\Type\Php\RoundFunctionReturnTypeExtension' => [['0322']],
		'PHPStan\Type\Php\StrtotimeFunctionReturnTypeExtension' => [['0323']],
		'PHPStan\Type\Php\RandomIntFunctionReturnTypeExtension' => [['0324']],
		'PHPStan\Type\Php\RangeFunctionReturnTypeExtension' => [['0325']],
		'PHPStan\Type\Php\AssertFunctionTypeSpecifyingExtension' => [['0326']],
		'PHPStan\Type\Php\ClassExistsFunctionTypeSpecifyingExtension' => [['0327']],
		'PHPStan\Type\Php\ClassImplementsFunctionReturnTypeExtension' => [['0328']],
		'PHPStan\Type\Php\DefineConstantTypeSpecifyingExtension' => [['0329']],
		'PHPStan\Type\Php\DefinedConstantTypeSpecifyingExtension' => [['0330']],
		'PHPStan\Type\Php\FunctionExistsFunctionTypeSpecifyingExtension' => [['0331']],
		'PHPStan\Type\Php\InArrayFunctionTypeSpecifyingExtension' => [['0332']],
		'PHPStan\Type\Php\IsArrayFunctionTypeSpecifyingExtension' => [['0333']],
		'PHPStan\Type\Php\IsCallableFunctionTypeSpecifyingExtension' => [['0334']],
		'PHPStan\Type\Php\IsIterableFunctionTypeSpecifyingExtension' => [['0335']],
		'PHPStan\Type\Php\IsSubclassOfFunctionTypeSpecifyingExtension' => [['0336']],
		'PHPStan\Type\Php\IteratorToArrayFunctionReturnTypeExtension' => [['0337']],
		'PHPStan\Type\Php\IsAFunctionTypeSpecifyingExtension' => [['0338']],
		'PHPStan\Type\Php\IsAFunctionTypeSpecifyingHelper' => [['0339']],
		'PHPStan\Type\Php\CtypeDigitFunctionTypeSpecifyingExtension' => [['0340']],
		'PHPStan\Type\Php\JsonThrowOnErrorDynamicReturnTypeExtension' => [['0341']],
		'PHPStan\Type\Php\TypeSpecifyingFunctionsDynamicReturnTypeExtension' => [['0342']],
		'PHPStan\Type\Php\SimpleXMLElementAsXMLMethodReturnTypeExtension' => [['0343']],
		'PHPStan\Type\Php\SimpleXMLElementXpathMethodReturnTypeExtension' => [['0344']],
		'PHPStan\Type\Php\StrSplitFunctionReturnTypeExtension' => [['0345']],
		'PHPStan\Type\Php\StrTokFunctionReturnTypeExtension' => [['0346']],
		'PHPStan\Type\Php\SprintfFunctionDynamicReturnTypeExtension' => [['0347']],
		'PHPStan\Type\Php\SscanfFunctionDynamicReturnTypeExtension' => [['0348']],
		'PHPStan\Type\Php\StrvalFamilyFunctionReturnTypeExtension' => [['0349']],
		'PHPStan\Type\Php\StrWordCountFunctionDynamicReturnTypeExtension' => [['0350']],
		'PHPStan\Type\Php\XMLReaderOpenReturnTypeExtension' => [['0351']],
		'PHPStan\Type\Php\ReflectionGetAttributesMethodReturnTypeExtension' => [['0352', '0353', '0354', '0355', '0356']],
		'PHPStan\Type\Php\DatePeriodConstructorReturnTypeExtension' => [['0357']],
		'PHPStan\Type\PHPStan\ClassNameUsageLocationCreateIdentifierDynamicReturnTypeExtension' => [['0358']],
		'PHPStan\Type\ClosureTypeFactory' => [['0359']],
		'PHPStan\Type\Constant\OversizedArrayBuilder' => [['0360']],
		'PHPStan\Rules\Functions\PrintfHelper' => [['0361']],
		'PHPStan\Analyser\TypeSpecifier' => [['typeSpecifier']],
		'PHPStan\Analyser\TypeSpecifierFactory' => [['typeSpecifierFactory']],
		'PHPStan\File\RelativePathHelper' => [
			0 => ['relativePathHelper'],
			2 => [1 => 'simpleRelativePathHelper', 'parentDirectoryRelativePathHelper'],
		],
		'PHPStan\File\ParentDirectoryRelativePathHelper' => [2 => ['parentDirectoryRelativePathHelper']],
		'PHPStan\Cache\CacheStorage' => [2 => ['cacheStorage']],
		'PHPStan\Cache\FileCacheStorage' => [2 => ['cacheStorage']],
		'PHPStan\Parser\Parser' => [
			2 => [
				'currentPhpVersionRichParser',
				'currentPhpVersionSimpleParser',
				'currentPhpVersionSimpleDirectParser',
				'defaultAnalysisParser',
				'php8Parser',
				'pathRoutingParser',
				'freshStubParser',
				'stubParser',
			],
		],
		'PHPStan\Parser\RichParser' => [2 => ['currentPhpVersionRichParser']],
		'PHPStan\Parser\CleaningParser' => [2 => ['currentPhpVersionSimpleParser']],
		'PHPStan\Parser\SimpleParser' => [2 => ['currentPhpVersionSimpleDirectParser', 'php8Parser']],
		'PHPStan\Parser\CachedParser' => [2 => ['defaultAnalysisParser', 'stubParser']],
		'PhpParser\Parser' => [2 => ['phpParserDecorator', 'currentPhpVersionPhpParser', 'php8PhpParser']],
		'PHPStan\Parser\PhpParserDecorator' => [2 => ['phpParserDecorator']],
		'PhpParser\Lexer' => [2 => ['currentPhpVersionLexer', 'php8Lexer']],
		'PhpParser\ParserAbstract' => [2 => ['currentPhpVersionPhpParser', 'php8PhpParser']],
		'PHPStan\Parser\PhpParserFactory' => [2 => ['currentPhpVersionPhpParserFactory']],
		'PHPStan\Rules\Registry' => [['registry']],
		'PHPStan\Rules\LazyRegistry' => [['registry']],
		'PHPStan\PhpDoc\StubPhpDocProvider' => [['stubPhpDocProvider']],
		'PHPStan\Reflection\ReflectionProvider\ReflectionProviderFactory' => [['reflectionProviderFactory']],
		'PHPStan\Reflection\ReflectionProvider' => [0 => ['reflectionProvider'], 2 => [1 => 'betterReflectionProvider']],
		'PHPStan\BetterReflection\SourceLocator\Type\SourceLocator' => [2 => ['betterReflectionSourceLocator']],
		'PHPStan\BetterReflection\Reflector\Reflector' => [
			0 => ['originalBetterReflectionReflector'],
			2 => [1 => 'betterReflectionReflector', 'nodeScopeResolverReflector'],
		],
		'PHPStan\BetterReflection\Reflector\DefaultReflector' => [['originalBetterReflectionReflector']],
		'PHPStan\Reflection\BetterReflection\Reflector\MemoizingReflector' => [
			2 => ['betterReflectionReflector', 'nodeScopeResolverReflector'],
		],
		'PHPStan\Reflection\BetterReflection\BetterReflectionProvider' => [2 => ['betterReflectionProvider']],
		'PHPStan\Reflection\BetterReflection\BetterReflectionSourceLocatorFactory' => [['0362']],
		'PHPStan\Reflection\BetterReflection\BetterReflectionProviderFactory' => [['0363']],
		'PHPStan\Reflection\BetterReflection\SourceStubber\PhpStormStubsSourceStubberFactory' => [['0364']],
		'PHPStan\BetterReflection\SourceLocator\SourceStubber\SourceStubber' => [1 => ['0365', '0366']],
		'PHPStan\BetterReflection\SourceLocator\SourceStubber\PhpStormStubsSourceStubber' => [['0365']],
		'PHPStan\BetterReflection\SourceLocator\SourceStubber\ReflectionSourceStubber' => [['0366']],
		'PHPStan\Reflection\BetterReflection\SourceStubber\ReflectionSourceStubberFactory' => [['0367']],
		'PHPStan\Reflection\Deprecation\DeprecationProvider' => [['0368']],
		'PhpParser\Lexer\Emulative' => [2 => ['php8Lexer']],
		'PhpParser\Parser\Php8' => [2 => ['php8PhpParser']],
		'PHPStan\Parser\PathRoutingParser' => [2 => ['pathRoutingParser']],
		'PHPStan\Parser\StubParser' => [2 => ['freshStubParser']],
		'PHPStan\Diagnose\PHPStanDiagnoseExtension' => [2 => ['phpstanDiagnoseExtension']],
		'PHPStan\Command\ErrorFormatter\ErrorFormatter' => [
			[
				'errorFormatter.raw',
				'errorFormatter.table',
				'errorFormatter.checkstyle',
				'errorFormatter.json',
				'errorFormatter.junit',
				'errorFormatter.prettyJson',
				'errorFormatter.gitlab',
				'errorFormatter.github',
				'errorFormatter.teamcity',
			],
			['0369'],
		],
		'PHPStan\Command\ErrorFormatter\CiDetectedErrorFormatter' => [['0369']],
		'PHPStan\Command\ErrorFormatter\RawErrorFormatter' => [['errorFormatter.raw']],
		'PHPStan\Command\ErrorFormatter\TableErrorFormatter' => [['errorFormatter.table']],
		'PHPStan\Command\ErrorFormatter\CheckstyleErrorFormatter' => [['errorFormatter.checkstyle']],
		'PHPStan\Command\ErrorFormatter\JsonErrorFormatter' => [['errorFormatter.json', 'errorFormatter.prettyJson']],
		'PHPStan\Command\ErrorFormatter\JunitErrorFormatter' => [['errorFormatter.junit']],
		'PHPStan\Command\ErrorFormatter\GitlabErrorFormatter' => [['errorFormatter.gitlab']],
		'PHPStan\Command\ErrorFormatter\GithubErrorFormatter' => [['errorFormatter.github']],
		'PHPStan\Command\ErrorFormatter\TeamcityErrorFormatter' => [['errorFormatter.teamcity']],
		'PHPStan\Rules\Classes\ExistingClassInClassExtendsRule' => [['0370']],
		'PHPStan\Rules\Classes\ExistingClassesInClassImplementsRule' => [['0371']],
		'PHPStan\Rules\Classes\ExistingClassesInEnumImplementsRule' => [['0372']],
		'PHPStan\Rules\Classes\ExistingClassInInstanceOfRule' => [['0373']],
		'PHPStan\Rules\Classes\ExistingClassesInInterfaceExtendsRule' => [['0374']],
		'PHPStan\Rules\Classes\ExistingClassInTraitUseRule' => [['0375']],
		'PHPStan\Rules\Classes\InstantiationRule' => [['0376']],
		'PHPStan\Rules\Exceptions\CaughtExceptionExistenceRule' => [['0377']],
		'PHPStan\Rules\Functions\CallToNonExistentFunctionRule' => [['0378']],
		'PHPStan\Rules\Classes\NewStaticInAbstractClassStaticMethodRule' => [['0379']],
		'PHPStan\Rules\Constants\OverridingConstantRule' => [['0380']],
		'PHPStan\Rules\Methods\OverridingMethodRule' => [['0381']],
		'PHPStan\Rules\Missing\MissingReturnRule' => [['0382']],
		'PHPStan\Rules\Namespaces\ExistingNamesInGroupUseRule' => [['0383']],
		'PHPStan\Rules\Namespaces\ExistingNamesInUseRule' => [['0384']],
		'PHPStan\Rules\Properties\AccessPropertiesRule' => [['0385']],
		'PHPStan\Rules\Properties\AccessStaticPropertiesRule' => [['0386']],
		'PHPStan\Rules\Properties\ExistingClassesInPropertiesRule' => [['0387']],
		'PHPStan\Rules\Functions\FunctionCallableRule' => [['0388']],
		'PHPStan\Rules\Properties\OverridingPropertyRule' => [['0389']],
		'PHPStan\Rules\Properties\SetPropertyHookParameterRule' => [['0390']],
		'PHPStan\Rules\Properties\WritingToReadOnlyPropertiesRule' => [['0391']],
		'PHPStan\Rules\Properties\ReadingWriteOnlyPropertiesRule' => [['0392']],
		'PHPStan\Rules\Variables\CompactVariablesRule' => [['0393']],
		'PHPStan\Rules\Variables\DefinedVariableRule' => [['0394']],
		'PHPStan\Rules\Keywords\RequireFileExistsRule' => [['0395']],
		'PHPStan\Rules\RestrictedUsage\RestrictedClassConstantUsageExtension' => [['0396', '0436']],
		'PHPStan\Rules\InternalTag\RestrictedInternalClassConstantUsageExtension' => [['0396']],
		'PHPStan\Rules\RestrictedUsage\RestrictedClassNameUsageExtension' => [['0397', '0440']],
		'PHPStan\Rules\InternalTag\RestrictedInternalClassNameUsageExtension' => [['0397']],
		'PHPStan\Rules\RestrictedUsage\RestrictedFunctionUsageExtension' => [['0398', '0437']],
		'PHPStan\Rules\InternalTag\RestrictedInternalFunctionUsageExtension' => [['0398']],
		'Composer\PHPStan\ConfigReturnTypeExtension' => [['0399']],
		'Composer\PHPStan\RuleReasonDataReturnTypeExtension' => [['0400']],
		'PHPStan\Type\StaticMethodParameterOutTypeExtension' => [['0401']],
		'Composer\Pcre\PHPStan\PregMatchParameterOutTypeExtension' => [['0401']],
		'PHPStan\Type\StaticMethodTypeSpecifyingExtension' => [['0402', '0426', '0444']],
		'Composer\Pcre\PHPStan\PregMatchTypeSpecifyingExtension' => [['0402']],
		'PHPStan\Type\StaticMethodParameterClosureTypeExtension' => [['0403']],
		'Composer\Pcre\PHPStan\PregReplaceCallbackClosureTypeExtension' => [['0403']],
		'mglaman\PHPStanDrupal\Drupal\ServiceMap' => [['0404']],
		'mglaman\PHPStanDrupal\Drupal\ExtensionMap' => [['0405']],
		'mglaman\PHPStanDrupal\Drupal\EntityDataRepository' => [['0406']],
		'mglaman\PHPStanDrupal\Type\EntityTypeManagerGetStorageDynamicReturnTypeExtension' => [['0407']],
		'mglaman\PHPStanDrupal\Type\EntityStorage\EntityStorageDynamicReturnTypeExtension' => [['0408']],
		'mglaman\PHPStanDrupal\Type\EntityRepositoryReturnTypeExtension' => [['0409']],
		'mglaman\PHPStanDrupal\Type\EntityStorage\GetQueryReturnTypeExtension' => [['0410']],
		'mglaman\PHPStanDrupal\Type\ContainerDynamicReturnTypeExtension' => [['0411']],
		'mglaman\PHPStanDrupal\Type\DrupalClassResolverDynamicReturnTypeExtension' => [['0412']],
		'mglaman\PHPStanDrupal\Type\EntityQuery\EntityQueryDynamicReturnTypeExtension' => [['0413']],
		'mglaman\PHPStanDrupal\Type\EntityQuery\EntityQueryAccessCheckDynamicReturnTypeExtension' => [['0414']],
		'mglaman\PHPStanDrupal\Type\EntityAccessControlHandlerReturnTypeExtension' => [['0415']],
		'mglaman\PHPStanDrupal\Type\DrupalClassResolverDynamicStaticReturnTypeExtension' => [['0416']],
		'mglaman\PHPStanDrupal\Type\DrupalServiceDynamicReturnTypeExtension' => [['0417']],
		'mglaman\PHPStanDrupal\Type\DrupalStaticEntityQueryDynamicReturnTypeExtension' => [['0418']],
		'mglaman\PHPStanDrupal\Reflection\EntityFieldsViaMagicReflectionExtension' => [['0419']],
		'mglaman\PHPStanDrupal\Reflection\EntityFieldMethodsViaMagicReflectionExtension' => [['0420']],
		'mglaman\PHPStanDrupal\Drupal\DrupalStubFilesExtension' => [['0421']],
		'mglaman\PHPStanDrupal\Type\EntityQuery\AccessCheckTypeSpecifyingExtension' => [['0422']],
		'PHPStan\Rules\Deprecations\DeprecatedScopeResolver' => [['0423', '0424', '0425', '0434']],
		'mglaman\PHPStanDrupal\DeprecatedScope\GroupLegacyScope' => [['0423']],
		'mglaman\PHPStanDrupal\DeprecatedScope\IgnoreDeprecationsScope' => [['0424']],
		'mglaman\PHPStanDrupal\DeprecatedScope\DeprecationHelperScope' => [['0425']],
		'mglaman\PHPStanDrupal\Type\InspectorTypeExtension' => [['0426']],
		'mglaman\PHPStanDrupal\Rules\Drupal\Tests\TestClassSuffixNameRule' => [['0427']],
		'mglaman\PHPStanDrupal\Rules\Drupal\DependencySerializationTraitPropertyRule' => [['0428']],
		'mglaman\PHPStanDrupal\Rules\Drupal\AccessResultConditionRule' => [['0429']],
		'mglaman\PHPStanDrupal\Rules\Classes\ClassExtendsInternalClassRule' => [['0430']],
		'mglaman\PHPStanDrupal\Rules\Classes\PluginManagerInspectionRule' => [['0431']],
		'PHPStan\DependencyInjection\LazyDeprecatedScopeResolverProvider' => [['0432']],
		'PHPStan\Rules\Deprecations\DeprecatedScopeHelper' => [['0433']],
		'PHPStan\Rules\Deprecations\DefaultDeprecatedScopeResolver' => [['0434']],
		'PHPStan\Rules\Deprecations\CallWithDeprecatedIniOptionRule' => [['0435']],
		'PHPStan\Rules\Deprecations\RestrictedDeprecatedClassConstantUsageExtension' => [['0436']],
		'PHPStan\Rules\Deprecations\RestrictedDeprecatedFunctionUsageExtension' => [['0437']],
		'PHPStan\Rules\RestrictedUsage\RestrictedMethodUsageExtension' => [['0438']],
		'PHPStan\Rules\Deprecations\RestrictedDeprecatedMethodUsageExtension' => [['0438']],
		'PHPStan\Rules\RestrictedUsage\RestrictedPropertyUsageExtension' => [['0439']],
		'PHPStan\Rules\Deprecations\RestrictedDeprecatedPropertyUsageExtension' => [['0439']],
		'PHPStan\Rules\Deprecations\RestrictedDeprecatedClassNameUsageExtension' => [['0440']],
		'PHPStan\PhpDoc\TypeNodeResolverExtension' => [['0441']],
		'PHPStan\PhpDoc\TypeNodeResolverAwareExtension' => [['0441']],
		'PHPStan\PhpDoc\PHPUnit\MockObjectTypeNodeResolverExtension' => [['0441']],
		'PHPStan\Type\PHPUnit\Assert\AssertFunctionTypeSpecifyingExtension' => [['0442']],
		'PHPStan\Type\PHPUnit\Assert\AssertMethodTypeSpecifyingExtension' => [['0443']],
		'PHPStan\Type\PHPUnit\Assert\AssertStaticMethodTypeSpecifyingExtension' => [['0444']],
		'PHPStan\Type\PHPUnit\MockBuilderDynamicReturnTypeExtension' => [['0445']],
		'PHPStan\Rules\PHPUnit\CoversHelper' => [['0446']],
		'PHPStan\Rules\PHPUnit\AnnotationHelper' => [['0447']],
		'PHPStan\Rules\PHPUnit\DataProviderHelper' => [['0448']],
		'PHPStan\Rules\PHPUnit\DataProviderHelperFactory' => [['0449']],
		'PHPStan\Rules\PHPUnit\DataProviderDeclarationRule' => [['0450']],
		'PHPStan\Rules\PHPUnit\AssertEqualsIsDiscouragedRule' => [['0451']],
	];


	public function __construct(array $params = [])
	{
		parent::__construct($params);
	}


	public function createService01(): PhpParser\BuilderFactory
	{
		return new PhpParser\BuilderFactory;
	}


	public function createService02(): PHPStan\Parser\LexerFactory
	{
		return new PHPStan\Parser\LexerFactory($this->getService('026'));
	}


	public function createService03(): PhpParser\NodeVisitor\NameResolver
	{
		return new PhpParser\NodeVisitor\NameResolver(options: ['preserveOriginalNames' => true]);
	}


	public function createService04(): PHPStan\Parser\AnonymousClassVisitor
	{
		return new PHPStan\Parser\AnonymousClassVisitor;
	}


	public function createService05(): PHPStan\Parser\ArrayFilterArgVisitor
	{
		return new PHPStan\Parser\ArrayFilterArgVisitor;
	}


	public function createService06(): PHPStan\Parser\ArrayFindArgVisitor
	{
		return new PHPStan\Parser\ArrayFindArgVisitor;
	}


	public function createService07(): PHPStan\Parser\ArrayMapArgVisitor
	{
		return new PHPStan\Parser\ArrayMapArgVisitor;
	}


	public function createService08(): PHPStan\Parser\ArrayWalkArgVisitor
	{
		return new PHPStan\Parser\ArrayWalkArgVisitor;
	}


	public function createService09(): PHPStan\Parser\ClosureArgVisitor
	{
		return new PHPStan\Parser\ClosureArgVisitor;
	}


	public function createService010(): PHPStan\Parser\ClosureBindToVarVisitor
	{
		return new PHPStan\Parser\ClosureBindToVarVisitor;
	}


	public function createService011(): PHPStan\Parser\ClosureBindArgVisitor
	{
		return new PHPStan\Parser\ClosureBindArgVisitor;
	}


	public function createService012(): PHPStan\Parser\CurlSetOptArgVisitor
	{
		return new PHPStan\Parser\CurlSetOptArgVisitor;
	}


	public function createService013(): PHPStan\Parser\ArrowFunctionArgVisitor
	{
		return new PHPStan\Parser\ArrowFunctionArgVisitor;
	}


	public function createService014(): PHPStan\Parser\MagicConstantParamDefaultVisitor
	{
		return new PHPStan\Parser\MagicConstantParamDefaultVisitor;
	}


	public function createService015(): PHPStan\Parser\NewAssignedToPropertyVisitor
	{
		return new PHPStan\Parser\NewAssignedToPropertyVisitor;
	}


	public function createService016(): PHPStan\Parser\ParentStmtTypesVisitor
	{
		return new PHPStan\Parser\ParentStmtTypesVisitor;
	}


	public function createService017(): PHPStan\Parser\StandaloneThrowExprVisitor
	{
		return new PHPStan\Parser\StandaloneThrowExprVisitor;
	}


	public function createService018(): PHPStan\Parser\TryCatchTypeVisitor
	{
		return new PHPStan\Parser\TryCatchTypeVisitor;
	}


	public function createService019(): PHPStan\Parser\LastConditionVisitor
	{
		return new PHPStan\Parser\LastConditionVisitor;
	}


	public function createService020(): PHPStan\Parser\TypeTraverserInstanceofVisitor
	{
		return new PHPStan\Parser\TypeTraverserInstanceofVisitor;
	}


	public function createService021(): PHPStan\Parser\VariadicMethodsVisitor
	{
		return new PHPStan\Parser\VariadicMethodsVisitor;
	}


	public function createService022(): PHPStan\Parser\VariadicFunctionsVisitor
	{
		return new PHPStan\Parser\VariadicFunctionsVisitor;
	}


	public function createService023(): PHPStan\Node\Printer\ExprPrinter
	{
		return new PHPStan\Node\Printer\ExprPrinter($this->getService('024'));
	}


	public function createService024(): PHPStan\Node\Printer\Printer
	{
		return new PHPStan\Node\Printer\Printer;
	}


	public function createService025(): PHPStan\Broker\AnonymousClassNameHelper
	{
		return new PHPStan\Broker\AnonymousClassNameHelper($this->getService('085'), $this->getService('simpleRelativePathHelper'));
	}


	public function createService026(): PHPStan\Php\PhpVersion
	{
		return $this->getService('027')->create();
	}


	public function createService027(): PHPStan\Php\PhpVersionFactory
	{
		return $this->getService('028')->create();
	}


	public function createService028(): PHPStan\Php\PhpVersionFactoryFactory
	{
		return new PHPStan\Php\PhpVersionFactoryFactory(
			null,
			['/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal']
		);
	}


	public function createService029(): PHPStan\Php\ComposerPhpVersionFactory
	{
		return new PHPStan\Php\ComposerPhpVersionFactory([
			'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal',
		]);
	}


	public function createService030(): PHPStan\PhpDocParser\ParserConfig
	{
		return new PHPStan\PhpDocParser\ParserConfig(['lines' => true]);
	}


	public function createService031(): PHPStan\PhpDocParser\Lexer\Lexer
	{
		return new PHPStan\PhpDocParser\Lexer\Lexer($this->getService('030'));
	}


	public function createService032(): PHPStan\PhpDocParser\Parser\TypeParser
	{
		return new PHPStan\PhpDocParser\Parser\TypeParser($this->getService('030'), $this->getService('033'));
	}


	public function createService033(): PHPStan\PhpDocParser\Parser\ConstExprParser
	{
		return new PHPStan\PhpDocParser\Parser\ConstExprParser($this->getService('030'));
	}


	public function createService034(): PHPStan\PhpDocParser\Parser\PhpDocParser
	{
		return new PHPStan\PhpDocParser\Parser\PhpDocParser(
			$this->getService('030'),
			$this->getService('032'),
			$this->getService('033')
		);
	}


	public function createService035(): PHPStan\PhpDocParser\Printer\Printer
	{
		return new PHPStan\PhpDocParser\Printer\Printer;
	}


	public function createService036(): PHPStan\PhpDoc\PhpDocInheritanceResolver
	{
		return new PHPStan\PhpDoc\PhpDocInheritanceResolver($this->getService('0185'), $this->getService('stubPhpDocProvider'));
	}


	public function createService037(): PHPStan\PhpDoc\PhpDocNodeResolver
	{
		return new PHPStan\PhpDoc\PhpDocNodeResolver($this->getService('040'), $this->getService('039'), $this->getService('0170'));
	}


	public function createService038(): PHPStan\PhpDoc\PhpDocStringResolver
	{
		return new PHPStan\PhpDoc\PhpDocStringResolver($this->getService('031'), $this->getService('034'));
	}


	public function createService039(): PHPStan\PhpDoc\ConstExprNodeResolver
	{
		return new PHPStan\PhpDoc\ConstExprNodeResolver($this->getService('0122'), $this->getService('096'));
	}


	public function createService040(): PHPStan\PhpDoc\TypeNodeResolver
	{
		return new PHPStan\PhpDoc\TypeNodeResolver(
			$this->getService('041'),
			$this->getService('0122'),
			$this->getService('0187'),
			$this->getService('060'),
			$this->getService('096')
		);
	}


	public function createService041(): PHPStan\PhpDoc\TypeNodeResolverExtensionRegistryProvider
	{
		return new PHPStan\PhpDoc\LazyTypeNodeResolverExtensionRegistryProvider($this->getService('075'));
	}


	public function createService042(): PHPStan\PhpDoc\TypeStringResolver
	{
		return new PHPStan\PhpDoc\TypeStringResolver($this->getService('031'), $this->getService('032'), $this->getService('040'));
	}


	public function createService043(): PHPStan\PhpDoc\StubValidator
	{
		return new PHPStan\PhpDoc\StubValidator($this->getService('077'));
	}


	public function createService044(): PHPStan\PhpDoc\SocketSelectStubFilesExtension
	{
		return new PHPStan\PhpDoc\SocketSelectStubFilesExtension($this->getService('026'));
	}


	public function createService045(): PHPStan\PhpDoc\DefaultStubFilesProvider
	{
		return new PHPStan\PhpDoc\DefaultStubFilesProvider(
			$this->getService('075'),
			[
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionAttribute.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionClassConstant.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionFunctionAbstract.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionMethod.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionParameter.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionProperty.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/iterable.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ArrayObject.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/WeakReference.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ext-ds.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ImagickPixel.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/PDOStatement.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/date.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ibm_db2.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/mysqli.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/zip.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/dom.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/spl.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/SplObjectStorage.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/Exception.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/arrayFunctions.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/core.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/typeCheckingFunctions.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/Countable.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/Assert.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/AssertionFailedError.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/ExpectationFailedException.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/MockBuilder.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/MockObject.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/Stub.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/TestCase.stub',
			],
			['/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal']
		);
	}


	public function createService046(): PHPStan\PhpDoc\JsonValidateStubFilesExtension
	{
		return new PHPStan\PhpDoc\JsonValidateStubFilesExtension($this->getService('026'));
	}


	public function createService047(): PHPStan\PhpDoc\ReflectionClassStubFilesExtension
	{
		return new PHPStan\PhpDoc\ReflectionClassStubFilesExtension($this->getService('026'));
	}


	public function createService048(): PHPStan\PhpDoc\ReflectionEnumStubFilesExtension
	{
		return new PHPStan\PhpDoc\ReflectionEnumStubFilesExtension($this->getService('026'));
	}


	public function createService049(): PHPStan\Analyser\Analyser
	{
		return new PHPStan\Analyser\Analyser(
			$this->getService('051'),
			$this->getService('registry'),
			$this->getService('066'),
			$this->getService('059'),
			50
		);
	}


	public function createService050(): PHPStan\Analyser\AnalyserResultFinalizer
	{
		return new PHPStan\Analyser\AnalyserResultFinalizer(
			$this->getService('registry'),
			$this->getService('052'),
			$this->getService('054'),
			$this->getService('058'),
			$this->getService('053'),
			true
		);
	}


	public function createService051(): PHPStan\Analyser\FileAnalyser
	{
		return new PHPStan\Analyser\FileAnalyser(
			$this->getService('058'),
			$this->getService('059'),
			$this->getService('defaultAnalysisParser'),
			$this->getService('071'),
			$this->getService('052'),
			$this->getService('054'),
			$this->getService('053')
		);
	}


	public function createService052(): PHPStan\Analyser\IgnoreErrorExtensionProvider
	{
		return new PHPStan\Analyser\IgnoreErrorExtensionProvider($this->getService('075'));
	}


	public function createService053(): PHPStan\Analyser\LocalIgnoresProcessor
	{
		return new PHPStan\Analyser\LocalIgnoresProcessor;
	}


	public function createService054(): PHPStan\Analyser\RuleErrorTransformer
	{
		return new PHPStan\Analyser\RuleErrorTransformer;
	}


	public function createService055(): PHPStan\Analyser\Ignore\IgnoredErrorHelper
	{
		return new PHPStan\Analyser\Ignore\IgnoredErrorHelper(
			$this->getService('085'),
			['#Cannot call method [a-zA-Z]+\(\) on mixed#', '#Property .* does not accept array#'],
			true
		);
	}


	public function createService056(): PHPStan\Analyser\Ignore\IgnoreLexer
	{
		return new PHPStan\Analyser\Ignore\IgnoreLexer;
	}


	public function createService057(): PHPStan\Analyser\LazyInternalScopeFactory
	{
		return new PHPStan\Analyser\LazyInternalScopeFactory($this->getService('075'));
	}


	public function createService058(): PHPStan\Analyser\ScopeFactory
	{
		return new PHPStan\Analyser\ScopeFactory($this->getService('057'));
	}


	public function createService059(): PHPStan\Analyser\NodeScopeResolver
	{
		return new PHPStan\Analyser\NodeScopeResolver(
			$this->getService('reflectionProvider'),
			$this->getService('096'),
			$this->getService('nodeScopeResolverReflector'),
			$this->getService('078'),
			$this->getService('080'),
			$this->getService('defaultAnalysisParser'),
			$this->getService('0185'),
			$this->getService('stubPhpDocProvider'),
			$this->getService('026'),
			$this->getService('0128'),
			$this->getService('0368'),
			$this->getService('094'),
			$this->getService('036'),
			$this->getService('085'),
			$this->getService('typeSpecifier'),
			$this->getService('083'),
			$this->getService('0178'),
			$this->getService('084'),
			$this->getService('058'),
			true,
			true,
			true,
			['PHPUnit\Framework\Assert' => ['fail', 'markTestIncomplete', 'markTestSkipped']],
			[],
			['stdClass'],
			true,
			true,
			true
		);
	}


	public function createService060(): PHPStan\Analyser\ConstantResolver
	{
		return $this->getService('061')->create();
	}


	public function createService061(): PHPStan\Analyser\ConstantResolverFactory
	{
		return new PHPStan\Analyser\ConstantResolverFactory($this->getService('0122'), $this->getService('075'));
	}


	public function createService062(): PHPStan\Analyser\ResultCache\ResultCacheManagerFactory
	{
		return new class ($this) implements PHPStan\Analyser\ResultCache\ResultCacheManagerFactory {
			private $container;


			public function __construct(Container_b4e34e1e86 $container)
			{
				$this->container = $container;
			}


			public function create(array $fileReplacements): PHPStan\Analyser\ResultCache\ResultCacheManager
			{
				return new PHPStan\Analyser\ResultCache\ResultCacheManager(
					$this->container->getService('075'),
					$this->container->getService('072'),
					$this->container->getService('fileFinderScan'),
					$this->container->getService('reflectionProvider'),
					$this->container->getService('045'),
					$this->container->getService('085'),
					'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/var/phpstan/resultCache.php',
					$this->container->getParameter('analysedPaths'),
					$this->container->getParameter('analysedPathsFromConfig'),
					['/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal'],
					'0',
					null,
					[
						'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/ReflectionUnionType.php',
						'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/ReflectionAttribute.php',
						'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/Attribute.php',
						'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/ReflectionIntersectionType.php',
						'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/drupal-autoloader.php',
						'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/web/core/tests/bootstrap.php',
					],
					[
						'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/stubs/Twig/functions.stub',
					],
					[],
					$fileReplacements,
					false,
					[
						['parameters', 'editorUrl'],
						['parameters', 'editorUrlTitle'],
						['parameters', 'errorFormat'],
						['parameters', 'ignoreErrors'],
						['parameters', 'reportUnmatchedIgnoredErrors'],
						['parameters', 'tipsOfTheDay'],
						['parameters', 'parallel'],
						['parameters', 'internalErrorsCountLimit'],
						['parameters', 'cache'],
						['parameters', 'memoryLimitFile'],
						['parameters', 'pro'],
						'parametersSchema',
					],
					7
				);
			}
		};
	}


	public function createService063(): PHPStan\Analyser\ResultCache\ResultCacheClearer
	{
		return new PHPStan\Analyser\ResultCache\ResultCacheClearer('/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/var/phpstan/resultCache.php');
	}


	public function createService064(): PHPStan\Analyser\RicherScopeGetTypeHelper
	{
		return new PHPStan\Analyser\RicherScopeGetTypeHelper($this->getService('096'));
	}


	public function createService065(): PHPStan\Cache\Cache
	{
		return new PHPStan\Cache\Cache($this->getService('cacheStorage'));
	}


	public function createService066(): PHPStan\Collectors\Registry
	{
		return $this->getService('067')->create();
	}


	public function createService067(): PHPStan\Collectors\RegistryFactory
	{
		return new PHPStan\Collectors\RegistryFactory($this->getService('075'));
	}


	public function createService068(): PHPStan\Command\AnalyseApplication
	{
		return new PHPStan\Command\AnalyseApplication(
			$this->getService('069'),
			$this->getService('050'),
			$this->getService('043'),
			$this->getService('062'),
			$this->getService('055'),
			$this->getService('045')
		);
	}


	public function createService069(): PHPStan\Command\AnalyserRunner
	{
		return new PHPStan\Command\AnalyserRunner(
			$this->getService('092'),
			$this->getService('049'),
			$this->getService('091'),
			$this->getService('093')
		);
	}


	public function createService070(): PHPStan\Command\FixerApplication
	{
		return new PHPStan\Command\FixerApplication(
			$this->getService('088'),
			$this->getService('055'),
			$this->getService('045'),
			$this->getParameter('analysedPaths'),
			'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal',
			($this->getParameter('sysGetTempDir')) . '/phpstan-fixer',
			['1.1.1.2'],
			['/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal'],
			[
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/conf/parametersSchema.neon',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/conf/config.level0.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/composer/composer/phpstan/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/composer/pcre/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-deprecation-rules/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/phpstan-basic.neon',
			],
			null,
			[
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/ReflectionUnionType.php',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/ReflectionAttribute.php',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/Attribute.php',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/ReflectionIntersectionType.php',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/drupal-autoloader.php',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/web/core/tests/bootstrap.php',
			],
			null,
			'0'
		);
	}


	public function createService071(): PHPStan\Dependency\DependencyResolver
	{
		return new PHPStan\Dependency\DependencyResolver(
			$this->getService('085'),
			$this->getService('reflectionProvider'),
			$this->getService('073'),
			$this->getService('0185')
		);
	}


	public function createService072(): PHPStan\Dependency\ExportedNodeFetcher
	{
		return new PHPStan\Dependency\ExportedNodeFetcher($this->getService('defaultAnalysisParser'), $this->getService('074'));
	}


	public function createService073(): PHPStan\Dependency\ExportedNodeResolver
	{
		return new PHPStan\Dependency\ExportedNodeResolver(
			$this->getService('reflectionProvider'),
			$this->getService('0185'),
			$this->getService('023')
		);
	}


	public function createService074(): PHPStan\Dependency\ExportedNodeVisitor
	{
		return new PHPStan\Dependency\ExportedNodeVisitor($this->getService('073'));
	}


	public function createService075(): PHPStan\DependencyInjection\Container
	{
		return new PHPStan\DependencyInjection\MemoizingContainer($this->getService('076'));
	}


	public function createService076(): PHPStan\DependencyInjection\Nette\NetteContainer
	{
		return new PHPStan\DependencyInjection\Nette\NetteContainer($this);
	}


	public function createService077(): PHPStan\DependencyInjection\DerivativeContainerFactory
	{
		return new PHPStan\DependencyInjection\DerivativeContainerFactory(
			'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal',
			'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/var/phpstan',
			[
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/conf/config.level0.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../composer/composer/phpstan/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../composer/pcre/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../mglaman/phpstan-drupal/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../mglaman/phpstan-drupal/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../phpstan-deprecation-rules/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../phpstan-phpunit/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../phpstan-phpunit/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/../phpstan-basic.neon',
			],
			$this->getParameter('analysedPaths'),
			['/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal'],
			$this->getParameter('analysedPathsFromConfig'),
			'0',
			null,
			null,
			$this->getParameter('singleReflectionFile'),
			$this->getParameter('singleReflectionInsteadOfFile')
		);
	}


	public function createService078(): PHPStan\DependencyInjection\Reflection\ClassReflectionExtensionRegistryProvider
	{
		return new PHPStan\DependencyInjection\Reflection\LazyClassReflectionExtensionRegistryProvider($this->getService('075'));
	}


	public function createService079(): PHPStan\DependencyInjection\Type\DynamicReturnTypeExtensionRegistryProvider
	{
		return new PHPStan\DependencyInjection\Type\LazyDynamicReturnTypeExtensionRegistryProvider($this->getService('075'));
	}


	public function createService080(): PHPStan\DependencyInjection\Type\ParameterOutTypeExtensionProvider
	{
		return new PHPStan\DependencyInjection\Type\LazyParameterOutTypeExtensionProvider($this->getService('075'));
	}


	public function createService081(): PHPStan\DependencyInjection\Type\ExpressionTypeResolverExtensionRegistryProvider
	{
		return new PHPStan\DependencyInjection\Type\LazyExpressionTypeResolverExtensionRegistryProvider($this->getService('075'));
	}


	public function createService082(): PHPStan\DependencyInjection\Type\OperatorTypeSpecifyingExtensionRegistryProvider
	{
		return new PHPStan\DependencyInjection\Type\LazyOperatorTypeSpecifyingExtensionRegistryProvider($this->getService('075'));
	}


	public function createService083(): PHPStan\DependencyInjection\Type\DynamicThrowTypeExtensionProvider
	{
		return new PHPStan\DependencyInjection\Type\LazyDynamicThrowTypeExtensionProvider($this->getService('075'));
	}


	public function createService084(): PHPStan\DependencyInjection\Type\ParameterClosureTypeExtensionProvider
	{
		return new PHPStan\DependencyInjection\Type\LazyParameterClosureTypeExtensionProvider($this->getService('075'));
	}


	public function createService085(): PHPStan\File\FileHelper
	{
		return new PHPStan\File\FileHelper('/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal');
	}


	public function createService086(): PHPStan\File\FileExcluderFactory
	{
		return new PHPStan\File\FileExcluderFactory(
			$this->getService('087'),
			['analyseAndScan' => ['*.api.php', '*/tests/fixtures/*.php'], 'analyse' => []]
		);
	}


	public function createService087(): PHPStan\File\FileExcluderRawFactory
	{
		return new class ($this) implements PHPStan\File\FileExcluderRawFactory {
			private $container;


			public function __construct(Container_b4e34e1e86 $container)
			{
				$this->container = $container;
			}


			public function create(array $analyseExcludes): PHPStan\File\FileExcluder
			{
				return new PHPStan\File\FileExcluder($this->container->getService('085'), $analyseExcludes);
			}
		};
	}


	public function createService088(): PHPStan\File\FileMonitor
	{
		return new PHPStan\File\FileMonitor(
			$this->getService('fileFinderAnalyse'),
			$this->getService('fileFinderScan'),
			$this->getParameter('analysedPaths'),
			$this->getParameter('analysedPathsFromConfig'),
			[
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/stubs/Twig/functions.stub',
			],
			[]
		);
	}


	public function createService089(): PHPStan\Parser\DeclarePositionVisitor
	{
		return new PHPStan\Parser\DeclarePositionVisitor;
	}


	public function createService090(): PHPStan\Parser\ImmediatelyInvokedClosureVisitor
	{
		return new PHPStan\Parser\ImmediatelyInvokedClosureVisitor;
	}


	public function createService091(): PHPStan\Parallel\ParallelAnalyser
	{
		return new PHPStan\Parallel\ParallelAnalyser(50, 600.0, 134217728);
	}


	public function createService092(): PHPStan\Parallel\Scheduler
	{
		return new PHPStan\Parallel\Scheduler(20, 32, 2);
	}


	public function createService093(): PHPStan\Process\CpuCoreCounter
	{
		return new PHPStan\Process\CpuCoreCounter;
	}


	public function createService094(): PHPStan\Reflection\AttributeReflectionFactory
	{
		return new PHPStan\Reflection\AttributeReflectionFactory($this->getService('096'), $this->getService('0122'));
	}


	public function createService095(): PHPStan\Reflection\FunctionReflectionFactory
	{
		return new class ($this) implements PHPStan\Reflection\FunctionReflectionFactory {
			private $container;


			public function __construct(Container_b4e34e1e86 $container)
			{
				$this->container = $container;
			}


			public function create(
				PHPStan\BetterReflection\Reflection\Adapter\ReflectionFunction $reflection,
				PHPStan\Type\Generic\TemplateTypeMap $templateTypeMap,
				array $phpDocParameterTypes,
				?PHPStan\Type\Type $phpDocReturnType,
				?PHPStan\Type\Type $phpDocThrowType,
				?string $deprecatedDescription,
				bool $isDeprecated,
				bool $isInternal,
				?string $filename,
				?bool $isPure,
				PHPStan\Reflection\Assertions $asserts,
				bool $acceptsNamedArguments,
				?string $phpDocComment,
				array $phpDocParameterOutTypes,
				array $phpDocParameterImmediatelyInvokedCallable,
				array $phpDocParameterClosureThisTypes,
				array $attributes
			): PHPStan\Reflection\Php\PhpFunctionReflection {
				return new PHPStan\Reflection\Php\PhpFunctionReflection(
					$this->container->getService('096'),
					$reflection,
					$this->container->getService('defaultAnalysisParser'),
					$this->container->getService('094'),
					$templateTypeMap,
					$phpDocParameterTypes,
					$phpDocReturnType,
					$phpDocThrowType,
					$deprecatedDescription,
					$isDeprecated,
					$isInternal,
					$filename,
					$isPure,
					$asserts,
					$acceptsNamedArguments,
					$phpDocComment,
					$phpDocParameterOutTypes,
					$phpDocParameterImmediatelyInvokedCallable,
					$phpDocParameterClosureThisTypes,
					$attributes
				);
			}
		};
	}


	public function createService096(): PHPStan\Reflection\InitializerExprTypeResolver
	{
		return new PHPStan\Reflection\InitializerExprTypeResolver(
			$this->getService('060'),
			$this->getService('0122'),
			$this->getService('026'),
			$this->getService('082'),
			$this->getService('0360'),
			false
		);
	}


	public function createService097(): PHPStan\Reflection\Annotations\AnnotationsMethodsClassReflectionExtension
	{
		return new PHPStan\Reflection\Annotations\AnnotationsMethodsClassReflectionExtension;
	}


	public function createService098(): PHPStan\Reflection\Annotations\AnnotationsPropertiesClassReflectionExtension
	{
		return new PHPStan\Reflection\Annotations\AnnotationsPropertiesClassReflectionExtension;
	}


	public function createService099(): PHPStan\Reflection\BetterReflection\SourceLocator\CachingVisitor
	{
		return new PHPStan\Reflection\BetterReflection\SourceLocator\CachingVisitor;
	}


	public function createService0100(): PHPStan\Reflection\BetterReflection\SourceLocator\FileNodesFetcher
	{
		return new PHPStan\Reflection\BetterReflection\SourceLocator\FileNodesFetcher(
			$this->getService('099'),
			$this->getService('defaultAnalysisParser')
		);
	}


	public function createService0101(): PHPStan\Reflection\BetterReflection\SourceLocator\ComposerJsonAndInstalledJsonSourceLocatorMaker
	{
		return new PHPStan\Reflection\BetterReflection\SourceLocator\ComposerJsonAndInstalledJsonSourceLocatorMaker(
			$this->getService('0103'),
			$this->getService('0104'),
			$this->getService('0102'),
			$this->getService('026')
		);
	}


	public function createService0102(): PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedDirectorySourceLocatorFactory
	{
		return new PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedDirectorySourceLocatorFactory(
			$this->getService('0100'),
			$this->getService('fileFinderScan'),
			$this->getService('026'),
			$this->getService('065')
		);
	}


	public function createService0103(): PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedDirectorySourceLocatorRepository
	{
		return new PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedDirectorySourceLocatorRepository($this->getService('0102'));
	}


	public function createService0104(): PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedPsrAutoloaderLocatorFactory
	{
		return new class ($this) implements PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedPsrAutoloaderLocatorFactory {
			private $container;


			public function __construct(Container_b4e34e1e86 $container)
			{
				$this->container = $container;
			}


			public function create(PHPStan\BetterReflection\SourceLocator\Type\Composer\Psr\PsrAutoloaderMapping $mapping): PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedPsrAutoloaderLocator
			{
				return new PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedPsrAutoloaderLocator($mapping, $this->container->getService('0106'));
			}
		};
	}


	public function createService0105(): PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedSingleFileSourceLocatorFactory
	{
		return new class ($this) implements PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedSingleFileSourceLocatorFactory {
			private $container;


			public function __construct(Container_b4e34e1e86 $container)
			{
				$this->container = $container;
			}


			public function create(string $fileName): PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedSingleFileSourceLocator
			{
				return new PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedSingleFileSourceLocator(
					$this->container->getService('0100'),
					$fileName
				);
			}
		};
	}


	public function createService0106(): PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedSingleFileSourceLocatorRepository
	{
		return new PHPStan\Reflection\BetterReflection\SourceLocator\OptimizedSingleFileSourceLocatorRepository($this->getService('0105'));
	}


	public function createService0107(): PHPStan\Reflection\BetterReflection\Type\AdapterReflectionEnumCaseDynamicReturnTypeExtension
	{
		return new PHPStan\Reflection\BetterReflection\Type\AdapterReflectionEnumCaseDynamicReturnTypeExtension(
			$this->getService('026'),
			'PHPStan\BetterReflection\Reflection\Adapter\ReflectionEnumBackedCase'
		);
	}


	public function createService0108(): PHPStan\Reflection\BetterReflection\Type\AdapterReflectionEnumCaseDynamicReturnTypeExtension
	{
		return new PHPStan\Reflection\BetterReflection\Type\AdapterReflectionEnumCaseDynamicReturnTypeExtension(
			$this->getService('026'),
			'PHPStan\BetterReflection\Reflection\Adapter\ReflectionEnumUnitCase'
		);
	}


	public function createService0109(): PHPStan\Reflection\BetterReflection\Type\AdapterReflectionEnumDynamicReturnTypeExtension
	{
		return new PHPStan\Reflection\BetterReflection\Type\AdapterReflectionEnumDynamicReturnTypeExtension($this->getService('026'));
	}


	public function createService0110(): PHPStan\Reflection\ConstructorsHelper
	{
		return new PHPStan\Reflection\ConstructorsHelper($this->getService('075'), ['PHPUnit\Framework\TestCase::setUp']);
	}


	public function createService0111(): PHPStan\Reflection\RequireExtension\RequireExtendsMethodsClassReflectionExtension
	{
		return new PHPStan\Reflection\RequireExtension\RequireExtendsMethodsClassReflectionExtension;
	}


	public function createService0112(): PHPStan\Reflection\RequireExtension\RequireExtendsPropertiesClassReflectionExtension
	{
		return new PHPStan\Reflection\RequireExtension\RequireExtendsPropertiesClassReflectionExtension;
	}


	public function createService0113(): PHPStan\Reflection\Mixin\MixinMethodsClassReflectionExtension
	{
		return new PHPStan\Reflection\Mixin\MixinMethodsClassReflectionExtension([]);
	}


	public function createService0114(): PHPStan\Reflection\Mixin\MixinPropertiesClassReflectionExtension
	{
		return new PHPStan\Reflection\Mixin\MixinPropertiesClassReflectionExtension([]);
	}


	public function createService0115(): PHPStan\Reflection\Php\PhpClassReflectionExtension
	{
		return new PHPStan\Reflection\Php\PhpClassReflectionExtension(
			$this->getService('058'),
			$this->getService('059'),
			$this->getService('0116'),
			$this->getService('036'),
			$this->getService('0368'),
			$this->getService('097'),
			$this->getService('098'),
			$this->getService('0128'),
			$this->getService('defaultAnalysisParser'),
			$this->getService('stubPhpDocProvider'),
			$this->getService('0122'),
			$this->getService('0185'),
			$this->getService('094'),
			false
		);
	}


	public function createService0116(): PHPStan\Reflection\Php\PhpMethodReflectionFactory
	{
		return new class ($this) implements PHPStan\Reflection\Php\PhpMethodReflectionFactory {
			private $container;


			public function __construct(Container_b4e34e1e86 $container)
			{
				$this->container = $container;
			}


			public function create(
				PHPStan\Reflection\ClassReflection $declaringClass,
				?PHPStan\Reflection\ClassReflection $declaringTrait,
				PHPStan\BetterReflection\Reflection\Adapter\ReflectionMethod $reflection,
				PHPStan\Type\Generic\TemplateTypeMap $templateTypeMap,
				array $phpDocParameterTypes,
				?PHPStan\Type\Type $phpDocReturnType,
				?PHPStan\Type\Type $phpDocThrowType,
				?string $deprecatedDescription,
				bool $isDeprecated,
				bool $isInternal,
				bool $isFinal,
				?bool $isPure,
				PHPStan\Reflection\Assertions $asserts,
				?PHPStan\Type\Type $selfOutType,
				?string $phpDocComment,
				array $phpDocParameterOutTypes,
				array $immediatelyInvokedCallableParameters,
				array $phpDocClosureThisTypeParameters,
				bool $acceptsNamedArguments,
				array $attributes
			): PHPStan\Reflection\Php\PhpMethodReflection {
				return new PHPStan\Reflection\Php\PhpMethodReflection(
					$this->container->getService('096'),
					$declaringClass,
					$declaringTrait,
					$reflection,
					$this->container->getService('reflectionProvider'),
					$this->container->getService('094'),
					$this->container->getService('defaultAnalysisParser'),
					$templateTypeMap,
					$phpDocParameterTypes,
					$phpDocReturnType,
					$phpDocThrowType,
					$deprecatedDescription,
					$isDeprecated,
					$isInternal,
					$isFinal,
					$isPure,
					$asserts,
					$acceptsNamedArguments,
					$selfOutType,
					$phpDocComment,
					$phpDocParameterOutTypes,
					$immediatelyInvokedCallableParameters,
					$phpDocClosureThisTypeParameters,
					$attributes
				);
			}
		};
	}


	public function createService0117(): PHPStan\Reflection\Php\Soap\SoapClientMethodsClassReflectionExtension
	{
		return new PHPStan\Reflection\Php\Soap\SoapClientMethodsClassReflectionExtension;
	}


	public function createService0118(): PHPStan\Reflection\Php\EnumAllowedSubTypesClassReflectionExtension
	{
		return new PHPStan\Reflection\Php\EnumAllowedSubTypesClassReflectionExtension;
	}


	public function createService0119(): PHPStan\Reflection\Php\UniversalObjectCratesClassReflectionExtension
	{
		return new PHPStan\Reflection\Php\UniversalObjectCratesClassReflectionExtension(
			$this->getService('reflectionProvider'),
			['stdClass'],
			$this->getService('098')
		);
	}


	public function createService0120(): PHPStan\Reflection\PHPStan\NativeReflectionEnumReturnDynamicReturnTypeExtension
	{
		return new PHPStan\Reflection\PHPStan\NativeReflectionEnumReturnDynamicReturnTypeExtension(
			$this->getService('026'),
			'PHPStan\Reflection\ClassReflection',
			'getNativeReflection'
		);
	}


	public function createService0121(): PHPStan\Reflection\PHPStan\NativeReflectionEnumReturnDynamicReturnTypeExtension
	{
		return new PHPStan\Reflection\PHPStan\NativeReflectionEnumReturnDynamicReturnTypeExtension(
			$this->getService('026'),
			'PHPStan\Reflection\Php\BuiltinMethodReflection',
			'getDeclaringClass'
		);
	}


	public function createService0122(): PHPStan\Reflection\ReflectionProvider\ReflectionProviderProvider
	{
		return new PHPStan\Reflection\ReflectionProvider\LazyReflectionProviderProvider($this->getService('075'));
	}


	public function createService0123(): PHPStan\Reflection\SignatureMap\NativeFunctionReflectionProvider
	{
		return new PHPStan\Reflection\SignatureMap\NativeFunctionReflectionProvider(
			$this->getService('0128'),
			$this->getService('betterReflectionReflector'),
			$this->getService('0185'),
			$this->getService('stubPhpDocProvider'),
			$this->getService('094')
		);
	}


	public function createService0124(): PHPStan\Reflection\SignatureMap\SignatureMapParser
	{
		return new PHPStan\Reflection\SignatureMap\SignatureMapParser($this->getService('042'));
	}


	public function createService0125(): PHPStan\Reflection\SignatureMap\FunctionSignatureMapProvider
	{
		return new PHPStan\Reflection\SignatureMap\FunctionSignatureMapProvider(
			$this->getService('0124'),
			$this->getService('096'),
			$this->getService('026'),
			false
		);
	}


	public function createService0126(): PHPStan\Reflection\SignatureMap\Php8SignatureMapProvider
	{
		return new PHPStan\Reflection\SignatureMap\Php8SignatureMapProvider(
			$this->getService('0125'),
			$this->getService('0100'),
			$this->getService('0185'),
			$this->getService('026'),
			$this->getService('096'),
			$this->getService('0122')
		);
	}


	public function createService0127(): PHPStan\Reflection\SignatureMap\SignatureMapProviderFactory
	{
		return new PHPStan\Reflection\SignatureMap\SignatureMapProviderFactory(
			$this->getService('026'),
			$this->getService('0125'),
			$this->getService('0126')
		);
	}


	public function createService0128(): PHPStan\Reflection\SignatureMap\SignatureMapProvider
	{
		return $this->getService('0127')->create();
	}


	public function createService0129(): PHPStan\Rules\Api\ApiRuleHelper
	{
		return new PHPStan\Rules\Api\ApiRuleHelper;
	}


	public function createService0130(): PHPStan\Rules\AttributesCheck
	{
		return new PHPStan\Rules\AttributesCheck(
			$this->getService('reflectionProvider'),
			$this->getService('0147'),
			$this->getService('0132'),
			true
		);
	}


	public function createService0131(): PHPStan\Rules\Arrays\NonexistentOffsetInArrayDimFetchCheck
	{
		return new PHPStan\Rules\Arrays\NonexistentOffsetInArrayDimFetchCheck($this->getService('0182'), false, false, false);
	}


	public function createService0132(): PHPStan\Rules\ClassNameCheck
	{
		return new PHPStan\Rules\ClassNameCheck(
			$this->getService('0133'),
			$this->getService('0134'),
			$this->getService('reflectionProvider'),
			$this->getService('075')
		);
	}


	public function createService0133(): PHPStan\Rules\ClassCaseSensitivityCheck
	{
		return new PHPStan\Rules\ClassCaseSensitivityCheck($this->getService('reflectionProvider'), false);
	}


	public function createService0134(): PHPStan\Rules\ClassForbiddenNameCheck
	{
		return new PHPStan\Rules\ClassForbiddenNameCheck($this->getService('075'));
	}


	public function createService0135(): PHPStan\Rules\Classes\LocalTypeAliasesCheck
	{
		return new PHPStan\Rules\Classes\LocalTypeAliasesCheck(
			[],
			$this->getService('reflectionProvider'),
			$this->getService('040'),
			$this->getService('0164'),
			$this->getService('0132'),
			$this->getService('0170'),
			$this->getService('0153'),
			false,
			false,
			true
		);
	}


	public function createService0136(): PHPStan\Rules\Classes\MethodTagCheck
	{
		return new PHPStan\Rules\Classes\MethodTagCheck(
			$this->getService('reflectionProvider'),
			$this->getService('0132'),
			$this->getService('0153'),
			$this->getService('0164'),
			$this->getService('0170'),
			false,
			false,
			true
		);
	}


	public function createService0137(): PHPStan\Rules\Classes\MixinCheck
	{
		return new PHPStan\Rules\Classes\MixinCheck(
			$this->getService('reflectionProvider'),
			$this->getService('0132'),
			$this->getService('0153'),
			$this->getService('0164'),
			$this->getService('0170'),
			false,
			false,
			true
		);
	}


	public function createService0138(): PHPStan\Rules\Classes\PropertyTagCheck
	{
		return new PHPStan\Rules\Classes\PropertyTagCheck(
			$this->getService('reflectionProvider'),
			$this->getService('0132'),
			$this->getService('0153'),
			$this->getService('0164'),
			$this->getService('0170'),
			false,
			false,
			true
		);
	}


	public function createService0139(): PHPStan\Rules\Comparison\ConstantConditionRuleHelper
	{
		return new PHPStan\Rules\Comparison\ConstantConditionRuleHelper($this->getService('0140'), true);
	}


	public function createService0140(): PHPStan\Rules\Comparison\ImpossibleCheckTypeHelper
	{
		return new PHPStan\Rules\Comparison\ImpossibleCheckTypeHelper(
			$this->getService('reflectionProvider'),
			$this->getService('typeSpecifier'),
			['stdClass'],
			true
		);
	}


	public function createService0141(): PHPStan\Rules\Exceptions\DefaultExceptionTypeResolver
	{
		return new PHPStan\Rules\Exceptions\DefaultExceptionTypeResolver(
			$this->getService('reflectionProvider'),
			['#^PHPUnit\\\#', '#^SebastianBergmann\\\#'],
			[],
			[],
			[]
		);
	}


	public function createService0142(): PHPStan\Rules\Exceptions\MissingCheckedExceptionInFunctionThrowsRule
	{
		return new PHPStan\Rules\Exceptions\MissingCheckedExceptionInFunctionThrowsRule($this->getService('0145'));
	}


	public function createService0143(): PHPStan\Rules\Exceptions\MissingCheckedExceptionInMethodThrowsRule
	{
		return new PHPStan\Rules\Exceptions\MissingCheckedExceptionInMethodThrowsRule($this->getService('0145'));
	}


	public function createService0144(): PHPStan\Rules\Exceptions\MissingCheckedExceptionInPropertyHookThrowsRule
	{
		return new PHPStan\Rules\Exceptions\MissingCheckedExceptionInPropertyHookThrowsRule($this->getService('0145'));
	}


	public function createService0145(): PHPStan\Rules\Exceptions\MissingCheckedExceptionInThrowsCheck
	{
		return new PHPStan\Rules\Exceptions\MissingCheckedExceptionInThrowsCheck($this->getService('exceptionTypeResolver'));
	}


	public function createService0146(): PHPStan\Rules\Exceptions\TooWideThrowTypeCheck
	{
		return new PHPStan\Rules\Exceptions\TooWideThrowTypeCheck(true);
	}


	public function createService0147(): PHPStan\Rules\FunctionCallParametersCheck
	{
		return new PHPStan\Rules\FunctionCallParametersCheck(
			$this->getService('0182'),
			$this->getService('0165'),
			$this->getService('0170'),
			$this->getService('0180'),
			false,
			false,
			false,
			false
		);
	}


	public function createService0148(): PHPStan\Rules\FunctionDefinitionCheck
	{
		return new PHPStan\Rules\FunctionDefinitionCheck(
			$this->getService('reflectionProvider'),
			$this->getService('0132'),
			$this->getService('0170'),
			$this->getService('026'),
			false,
			true
		);
	}


	public function createService0149(): PHPStan\Rules\FunctionReturnTypeCheck
	{
		return new PHPStan\Rules\FunctionReturnTypeCheck($this->getService('0182'));
	}


	public function createService0150(): PHPStan\Rules\ParameterCastableToStringCheck
	{
		return new PHPStan\Rules\ParameterCastableToStringCheck($this->getService('0182'));
	}


	public function createService0151(): PHPStan\Rules\Generics\CrossCheckInterfacesHelper
	{
		return new PHPStan\Rules\Generics\CrossCheckInterfacesHelper;
	}


	public function createService0152(): PHPStan\Rules\Generics\GenericAncestorsCheck
	{
		return new PHPStan\Rules\Generics\GenericAncestorsCheck(
			$this->getService('reflectionProvider'),
			$this->getService('0153'),
			$this->getService('0156'),
			$this->getService('0170'),
			[],
			false
		);
	}


	public function createService0153(): PHPStan\Rules\Generics\GenericObjectTypeCheck
	{
		return new PHPStan\Rules\Generics\GenericObjectTypeCheck;
	}


	public function createService0154(): PHPStan\Rules\Generics\MethodTagTemplateTypeCheck
	{
		return new PHPStan\Rules\Generics\MethodTagTemplateTypeCheck($this->getService('0185'), $this->getService('0155'));
	}


	public function createService0155(): PHPStan\Rules\Generics\TemplateTypeCheck
	{
		return new PHPStan\Rules\Generics\TemplateTypeCheck(
			$this->getService('reflectionProvider'),
			$this->getService('0132'),
			$this->getService('0153'),
			$this->getService('0186'),
			false
		);
	}


	public function createService0156(): PHPStan\Rules\Generics\VarianceCheck
	{
		return new PHPStan\Rules\Generics\VarianceCheck;
	}


	public function createService0157(): PHPStan\Rules\InternalTag\RestrictedInternalUsageHelper
	{
		return new PHPStan\Rules\InternalTag\RestrictedInternalUsageHelper;
	}


	public function createService0158(): PHPStan\Rules\IssetCheck
	{
		return new PHPStan\Rules\IssetCheck($this->getService('0179'), $this->getService('0180'), false, true);
	}


	public function createService0159(): PHPStan\Rules\Methods\MethodCallCheck
	{
		return new PHPStan\Rules\Methods\MethodCallCheck(
			$this->getService('reflectionProvider'),
			$this->getService('0182'),
			false,
			false
		);
	}


	public function createService0160(): PHPStan\Rules\Methods\StaticMethodCallCheck
	{
		return new PHPStan\Rules\Methods\StaticMethodCallCheck(
			$this->getService('reflectionProvider'),
			$this->getService('0182'),
			$this->getService('0132'),
			false,
			true,
			false
		);
	}


	public function createService0161(): PHPStan\Rules\Methods\MethodSignatureRule
	{
		return new PHPStan\Rules\Methods\MethodSignatureRule($this->getService('0115'), false, false);
	}


	public function createService0162(): PHPStan\Rules\Methods\MethodParameterComparisonHelper
	{
		return new PHPStan\Rules\Methods\MethodParameterComparisonHelper($this->getService('026'));
	}


	public function createService0163(): PHPStan\Rules\Methods\MethodVisibilityComparisonHelper
	{
		return new PHPStan\Rules\Methods\MethodVisibilityComparisonHelper;
	}


	public function createService0164(): PHPStan\Rules\MissingTypehintCheck
	{
		return new PHPStan\Rules\MissingTypehintCheck(false, []);
	}


	public function createService0165(): PHPStan\Rules\NullsafeCheck
	{
		return new PHPStan\Rules\NullsafeCheck;
	}


	public function createService0166(): PHPStan\Rules\Constants\LazyAlwaysUsedClassConstantsExtensionProvider
	{
		return new PHPStan\Rules\Constants\LazyAlwaysUsedClassConstantsExtensionProvider($this->getService('075'));
	}


	public function createService0167(): PHPStan\Rules\Methods\LazyAlwaysUsedMethodExtensionProvider
	{
		return new PHPStan\Rules\Methods\LazyAlwaysUsedMethodExtensionProvider($this->getService('075'));
	}


	public function createService0168(): PHPStan\Rules\PhpDoc\ConditionalReturnTypeRuleHelper
	{
		return new PHPStan\Rules\PhpDoc\ConditionalReturnTypeRuleHelper;
	}


	public function createService0169(): PHPStan\Rules\PhpDoc\AssertRuleHelper
	{
		return new PHPStan\Rules\PhpDoc\AssertRuleHelper(
			$this->getService('096'),
			$this->getService('reflectionProvider'),
			$this->getService('0170'),
			$this->getService('0132'),
			$this->getService('0164'),
			$this->getService('0153'),
			false,
			false
		);
	}


	public function createService0170(): PHPStan\Rules\PhpDoc\UnresolvableTypeHelper
	{
		return new PHPStan\Rules\PhpDoc\UnresolvableTypeHelper;
	}


	public function createService0171(): PHPStan\Rules\PhpDoc\GenericCallableRuleHelper
	{
		return new PHPStan\Rules\PhpDoc\GenericCallableRuleHelper($this->getService('0155'));
	}


	public function createService0172(): PHPStan\Rules\PhpDoc\IncompatiblePhpDocTypeCheck
	{
		return new PHPStan\Rules\PhpDoc\IncompatiblePhpDocTypeCheck(
			$this->getService('0153'),
			$this->getService('0170'),
			$this->getService('0171')
		);
	}


	public function createService0173(): PHPStan\Rules\PhpDoc\VarTagTypeRuleHelper
	{
		return new PHPStan\Rules\PhpDoc\VarTagTypeRuleHelper(
			$this->getService('040'),
			$this->getService('0185'),
			$this->getService('reflectionProvider'),
			false,
			false
		);
	}


	public function createService0174(): PHPStan\Rules\Playground\NeverRuleHelper
	{
		return new PHPStan\Rules\Playground\NeverRuleHelper;
	}


	public function createService0175(): PHPStan\Rules\Properties\AccessPropertiesCheck
	{
		return new PHPStan\Rules\Properties\AccessPropertiesCheck(
			$this->getService('reflectionProvider'),
			$this->getService('0182'),
			$this->getService('026'),
			false,
			false
		);
	}


	public function createService0176(): PHPStan\Type\Php\BcMathNumberOperatorTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\BcMathNumberOperatorTypeSpecifyingExtension($this->getService('026'));
	}


	public function createService0177(): PHPStan\Rules\Properties\UninitializedPropertyRule
	{
		return new PHPStan\Rules\Properties\UninitializedPropertyRule($this->getService('0110'));
	}


	public function createService0178(): PHPStan\Rules\Properties\LazyReadWritePropertiesExtensionProvider
	{
		return new PHPStan\Rules\Properties\LazyReadWritePropertiesExtensionProvider($this->getService('075'));
	}


	public function createService0179(): PHPStan\Rules\Properties\PropertyDescriptor
	{
		return new PHPStan\Rules\Properties\PropertyDescriptor;
	}


	public function createService0180(): PHPStan\Rules\Properties\PropertyReflectionFinder
	{
		return new PHPStan\Rules\Properties\PropertyReflectionFinder;
	}


	public function createService0181(): PHPStan\Rules\Pure\FunctionPurityCheck
	{
		return new PHPStan\Rules\Pure\FunctionPurityCheck;
	}


	public function createService0182(): PHPStan\Rules\RuleLevelHelper
	{
		return new PHPStan\Rules\RuleLevelHelper($this->getService('reflectionProvider'), false, true, false, false, false, false, true);
	}


	public function createService0183(): PHPStan\Rules\UnusedFunctionParametersCheck
	{
		return new PHPStan\Rules\UnusedFunctionParametersCheck($this->getService('reflectionProvider'), false);
	}


	public function createService0184(): PHPStan\Rules\TooWideTypehints\TooWideParameterOutTypeCheck
	{
		return new PHPStan\Rules\TooWideTypehints\TooWideParameterOutTypeCheck;
	}


	public function createService0185(): PHPStan\Type\FileTypeMapper
	{
		return new PHPStan\Type\FileTypeMapper(
			$this->getService('0122'),
			$this->getService('defaultAnalysisParser'),
			$this->getService('038'),
			$this->getService('037'),
			$this->getService('025'),
			$this->getService('085')
		);
	}


	public function createService0186(): PHPStan\Type\TypeAliasResolver
	{
		return new PHPStan\Type\UsefulTypeAliasResolver(
			[],
			$this->getService('042'),
			$this->getService('040'),
			$this->getService('reflectionProvider')
		);
	}


	public function createService0187(): PHPStan\Type\TypeAliasResolverProvider
	{
		return new PHPStan\Type\LazyTypeAliasResolverProvider($this->getService('075'));
	}


	public function createService0188(): PHPStan\Type\BitwiseFlagHelper
	{
		return new PHPStan\Type\BitwiseFlagHelper($this->getService('reflectionProvider'));
	}


	public function createService0189(): PHPStan\Type\Php\AbsFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\AbsFunctionDynamicReturnTypeExtension;
	}


	public function createService0190(): PHPStan\Type\Php\ArgumentBasedFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArgumentBasedFunctionReturnTypeExtension;
	}


	public function createService0191(): PHPStan\Type\Php\ArrayChangeKeyCaseFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayChangeKeyCaseFunctionReturnTypeExtension;
	}


	public function createService0192(): PHPStan\Type\Php\ArrayIntersectKeyFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayIntersectKeyFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0193(): PHPStan\Type\Php\ArrayChunkFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayChunkFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0194(): PHPStan\Type\Php\ArrayColumnHelper
	{
		return new PHPStan\Type\Php\ArrayColumnHelper($this->getService('026'));
	}


	public function createService0195(): PHPStan\Type\Php\ArrayColumnFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayColumnFunctionReturnTypeExtension($this->getService('0194'));
	}


	public function createService0196(): PHPStan\Type\Php\ArrayCombineFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayCombineFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0197(): PHPStan\Type\Php\ArrayCurrentDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayCurrentDynamicReturnTypeExtension;
	}


	public function createService0198(): PHPStan\Type\Php\ArrayFillFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayFillFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0199(): PHPStan\Type\Php\ArrayFillKeysFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayFillKeysFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0200(): PHPStan\Type\Php\ArrayFilterFunctionReturnTypeHelper
	{
		return new PHPStan\Type\Php\ArrayFilterFunctionReturnTypeHelper($this->getService('reflectionProvider'));
	}


	public function createService0201(): PHPStan\Type\Php\ArrayFilterFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayFilterFunctionReturnTypeExtension($this->getService('0200'));
	}


	public function createService0202(): PHPStan\Type\Php\ArrayFlipFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayFlipFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0203(): PHPStan\Type\Php\ArrayFindFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayFindFunctionReturnTypeExtension($this->getService('0200'));
	}


	public function createService0204(): PHPStan\Type\Php\ArrayFindKeyFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayFindKeyFunctionReturnTypeExtension;
	}


	public function createService0205(): PHPStan\Type\Php\ArrayKeyDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayKeyDynamicReturnTypeExtension;
	}


	public function createService0206(): PHPStan\Type\Php\ArrayKeyExistsFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\ArrayKeyExistsFunctionTypeSpecifyingExtension;
	}


	public function createService0207(): PHPStan\Type\Php\ArrayKeyFirstDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayKeyFirstDynamicReturnTypeExtension;
	}


	public function createService0208(): PHPStan\Type\Php\ArrayKeyLastDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayKeyLastDynamicReturnTypeExtension;
	}


	public function createService0209(): PHPStan\Type\Php\ArrayKeysFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayKeysFunctionDynamicReturnTypeExtension($this->getService('026'));
	}


	public function createService0210(): PHPStan\Type\Php\ArrayMapFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayMapFunctionReturnTypeExtension;
	}


	public function createService0211(): PHPStan\Type\Php\ArrayMergeFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayMergeFunctionDynamicReturnTypeExtension;
	}


	public function createService0212(): PHPStan\Type\Php\ArrayNextDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayNextDynamicReturnTypeExtension;
	}


	public function createService0213(): PHPStan\Type\Php\ArrayPopFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayPopFunctionReturnTypeExtension;
	}


	public function createService0214(): PHPStan\Type\Php\ArrayRandFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayRandFunctionReturnTypeExtension;
	}


	public function createService0215(): PHPStan\Type\Php\ArrayReduceFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayReduceFunctionReturnTypeExtension;
	}


	public function createService0216(): PHPStan\Type\Php\ArrayReplaceFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayReplaceFunctionReturnTypeExtension;
	}


	public function createService0217(): PHPStan\Type\Php\ArrayReverseFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayReverseFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0218(): PHPStan\Type\Php\ArrayShiftFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayShiftFunctionReturnTypeExtension;
	}


	public function createService0219(): PHPStan\Type\Php\ArraySliceFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArraySliceFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0220(): PHPStan\Type\Php\ArraySpliceFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArraySpliceFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0221(): PHPStan\Type\Php\ArraySearchFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArraySearchFunctionDynamicReturnTypeExtension($this->getService('026'));
	}


	public function createService0222(): PHPStan\Type\Php\ArraySearchFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\ArraySearchFunctionTypeSpecifyingExtension;
	}


	public function createService0223(): PHPStan\Type\Php\ArrayValuesFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayValuesFunctionDynamicReturnTypeExtension($this->getService('026'));
	}


	public function createService0224(): PHPStan\Type\Php\ArraySumFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArraySumFunctionDynamicReturnTypeExtension;
	}


	public function createService0225(): PHPStan\Type\Php\AssertThrowTypeExtension
	{
		return new PHPStan\Type\Php\AssertThrowTypeExtension;
	}


	public function createService0226(): PHPStan\Type\Php\BackedEnumFromMethodDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\BackedEnumFromMethodDynamicReturnTypeExtension;
	}


	public function createService0227(): PHPStan\Type\Php\Base64DecodeDynamicFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\Base64DecodeDynamicFunctionReturnTypeExtension;
	}


	public function createService0228(): PHPStan\Type\Php\BcMathStringOrNullReturnTypeExtension
	{
		return new PHPStan\Type\Php\BcMathStringOrNullReturnTypeExtension($this->getService('026'));
	}


	public function createService0229(): PHPStan\Type\Php\ClosureBindDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ClosureBindDynamicReturnTypeExtension;
	}


	public function createService0230(): PHPStan\Type\Php\ClosureBindToDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ClosureBindToDynamicReturnTypeExtension;
	}


	public function createService0231(): PHPStan\Type\Php\ClosureFromCallableDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ClosureFromCallableDynamicReturnTypeExtension;
	}


	public function createService0232(): PHPStan\Type\Php\CompactFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\CompactFunctionReturnTypeExtension(false);
	}


	public function createService0233(): PHPStan\Type\Php\ConstantFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ConstantFunctionReturnTypeExtension($this->getService('0234'));
	}


	public function createService0234(): PHPStan\Type\Php\ConstantHelper
	{
		return new PHPStan\Type\Php\ConstantHelper;
	}


	public function createService0235(): PHPStan\Type\Php\CountFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\CountFunctionReturnTypeExtension;
	}


	public function createService0236(): PHPStan\Type\Php\CountCharsFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\CountCharsFunctionDynamicReturnTypeExtension($this->getService('026'));
	}


	public function createService0237(): PHPStan\Type\Php\CountFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\CountFunctionTypeSpecifyingExtension;
	}


	public function createService0238(): PHPStan\Type\Php\CurlGetinfoFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\CurlGetinfoFunctionDynamicReturnTypeExtension($this->getService('reflectionProvider'));
	}


	public function createService0239(): PHPStan\Type\Php\DateFunctionReturnTypeHelper
	{
		return new PHPStan\Type\Php\DateFunctionReturnTypeHelper;
	}


	public function createService0240(): PHPStan\Type\Php\DateFormatFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\DateFormatFunctionReturnTypeExtension($this->getService('0239'));
	}


	public function createService0241(): PHPStan\Type\Php\DateFormatMethodReturnTypeExtension
	{
		return new PHPStan\Type\Php\DateFormatMethodReturnTypeExtension($this->getService('0239'));
	}


	public function createService0242(): PHPStan\Type\Php\DateFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\DateFunctionReturnTypeExtension($this->getService('0239'));
	}


	public function createService0243(): PHPStan\Type\Php\DateIntervalConstructorThrowTypeExtension
	{
		return new PHPStan\Type\Php\DateIntervalConstructorThrowTypeExtension($this->getService('026'));
	}


	public function createService0244(): PHPStan\Type\Php\DateIntervalDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\DateIntervalDynamicReturnTypeExtension;
	}


	public function createService0245(): PHPStan\Type\Php\DateTimeCreateDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\DateTimeCreateDynamicReturnTypeExtension;
	}


	public function createService0246(): PHPStan\Type\Php\DateTimeDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\DateTimeDynamicReturnTypeExtension;
	}


	public function createService0247(): PHPStan\Type\Php\DateTimeModifyReturnTypeExtension
	{
		return new PHPStan\Type\Php\DateTimeModifyReturnTypeExtension($this->getService('026'), 'DateTime');
	}


	public function createService0248(): PHPStan\Type\Php\DateTimeModifyReturnTypeExtension
	{
		return new PHPStan\Type\Php\DateTimeModifyReturnTypeExtension($this->getService('026'), 'DateTimeImmutable');
	}


	public function createService0249(): PHPStan\Type\Php\DateTimeConstructorThrowTypeExtension
	{
		return new PHPStan\Type\Php\DateTimeConstructorThrowTypeExtension($this->getService('026'));
	}


	public function createService0250(): PHPStan\Type\Php\DateTimeModifyMethodThrowTypeExtension
	{
		return new PHPStan\Type\Php\DateTimeModifyMethodThrowTypeExtension($this->getService('026'));
	}


	public function createService0251(): PHPStan\Type\Php\DateTimeSubMethodThrowTypeExtension
	{
		return new PHPStan\Type\Php\DateTimeSubMethodThrowTypeExtension($this->getService('026'));
	}


	public function createService0252(): PHPStan\Type\Php\DateTimeZoneConstructorThrowTypeExtension
	{
		return new PHPStan\Type\Php\DateTimeZoneConstructorThrowTypeExtension($this->getService('026'));
	}


	public function createService0253(): PHPStan\Type\Php\DsMapDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\DsMapDynamicReturnTypeExtension;
	}


	public function createService0254(): PHPStan\Type\Php\DsMapDynamicMethodThrowTypeExtension
	{
		return new PHPStan\Type\Php\DsMapDynamicMethodThrowTypeExtension;
	}


	public function createService0255(): PHPStan\Type\Php\DioStatDynamicFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\DioStatDynamicFunctionReturnTypeExtension;
	}


	public function createService0256(): PHPStan\Type\Php\ExplodeFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ExplodeFunctionDynamicReturnTypeExtension($this->getService('026'));
	}


	public function createService0257(): PHPStan\Type\Php\FilterFunctionReturnTypeHelper
	{
		return new PHPStan\Type\Php\FilterFunctionReturnTypeHelper($this->getService('reflectionProvider'), $this->getService('026'));
	}


	public function createService0258(): PHPStan\Type\Php\FilterInputDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\FilterInputDynamicReturnTypeExtension($this->getService('0257'));
	}


	public function createService0259(): PHPStan\Type\Php\FilterVarDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\FilterVarDynamicReturnTypeExtension($this->getService('0257'));
	}


	public function createService0260(): PHPStan\Type\Php\FilterVarArrayDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\FilterVarArrayDynamicReturnTypeExtension(
			$this->getService('0257'),
			$this->getService('reflectionProvider')
		);
	}


	public function createService0261(): PHPStan\Type\Php\GetCalledClassDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\GetCalledClassDynamicReturnTypeExtension;
	}


	public function createService0262(): PHPStan\Type\Php\GetClassDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\GetClassDynamicReturnTypeExtension;
	}


	public function createService0263(): PHPStan\Type\Php\GetDebugTypeFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\GetDebugTypeFunctionReturnTypeExtension;
	}


	public function createService0264(): PHPStan\Type\Php\GetDefinedVarsFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\GetDefinedVarsFunctionReturnTypeExtension;
	}


	public function createService0265(): PHPStan\Type\Php\GetParentClassDynamicFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\GetParentClassDynamicFunctionReturnTypeExtension($this->getService('reflectionProvider'));
	}


	public function createService0266(): PHPStan\Type\Php\GettypeFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\GettypeFunctionReturnTypeExtension;
	}


	public function createService0267(): PHPStan\Type\Php\GettimeofdayDynamicFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\GettimeofdayDynamicFunctionReturnTypeExtension;
	}


	public function createService0268(): PHPStan\Type\Php\HashFunctionsReturnTypeExtension
	{
		return new PHPStan\Type\Php\HashFunctionsReturnTypeExtension($this->getService('026'));
	}


	public function createService0269(): PHPStan\Type\Php\HighlightStringDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\HighlightStringDynamicReturnTypeExtension($this->getService('026'));
	}


	public function createService0270(): PHPStan\Type\Php\IntdivThrowTypeExtension
	{
		return new PHPStan\Type\Php\IntdivThrowTypeExtension;
	}


	public function createService0271(): PHPStan\Type\Php\IniGetReturnTypeExtension
	{
		return new PHPStan\Type\Php\IniGetReturnTypeExtension;
	}


	public function createService0272(): PHPStan\Type\Php\JsonThrowTypeExtension
	{
		return new PHPStan\Type\Php\JsonThrowTypeExtension($this->getService('reflectionProvider'), $this->getService('0188'));
	}


	public function createService0273(): PHPStan\Type\Php\OpenSslEncryptParameterOutTypeExtension
	{
		return new PHPStan\Type\Php\OpenSslEncryptParameterOutTypeExtension;
	}


	public function createService0274(): PHPStan\Type\Php\ParseStrParameterOutTypeExtension
	{
		return new PHPStan\Type\Php\ParseStrParameterOutTypeExtension;
	}


	public function createService0275(): PHPStan\Type\Php\PregMatchTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\PregMatchTypeSpecifyingExtension($this->getService('0278'));
	}


	public function createService0276(): PHPStan\Type\Php\PregMatchParameterOutTypeExtension
	{
		return new PHPStan\Type\Php\PregMatchParameterOutTypeExtension($this->getService('0278'));
	}


	public function createService0277(): PHPStan\Type\Php\PregReplaceCallbackClosureTypeExtension
	{
		return new PHPStan\Type\Php\PregReplaceCallbackClosureTypeExtension($this->getService('0278'));
	}


	public function createService0278(): PHPStan\Type\Php\RegexArrayShapeMatcher
	{
		return new PHPStan\Type\Php\RegexArrayShapeMatcher(
			$this->getService('0279'),
			$this->getService('0280'),
			$this->getService('026')
		);
	}


	public function createService0279(): PHPStan\Type\Regex\RegexGroupParser
	{
		return new PHPStan\Type\Regex\RegexGroupParser($this->getService('026'), $this->getService('0280'));
	}


	public function createService0280(): PHPStan\Type\Regex\RegexExpressionHelper
	{
		return new PHPStan\Type\Regex\RegexExpressionHelper($this->getService('096'));
	}


	public function createService0281(): PHPStan\Type\Php\ReflectionClassConstructorThrowTypeExtension
	{
		return new PHPStan\Type\Php\ReflectionClassConstructorThrowTypeExtension;
	}


	public function createService0282(): PHPStan\Type\Php\ReflectionFunctionConstructorThrowTypeExtension
	{
		return new PHPStan\Type\Php\ReflectionFunctionConstructorThrowTypeExtension($this->getService('reflectionProvider'));
	}


	public function createService0283(): PHPStan\Type\Php\ReflectionMethodConstructorThrowTypeExtension
	{
		return new PHPStan\Type\Php\ReflectionMethodConstructorThrowTypeExtension($this->getService('reflectionProvider'));
	}


	public function createService0284(): PHPStan\Type\Php\ReflectionPropertyConstructorThrowTypeExtension
	{
		return new PHPStan\Type\Php\ReflectionPropertyConstructorThrowTypeExtension($this->getService('reflectionProvider'));
	}


	public function createService0285(): PHPStan\Type\Php\StrContainingTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\StrContainingTypeSpecifyingExtension;
	}


	public function createService0286(): PHPStan\Type\Php\SimpleXMLElementClassPropertyReflectionExtension
	{
		return new PHPStan\Type\Php\SimpleXMLElementClassPropertyReflectionExtension;
	}


	public function createService0287(): PHPStan\Type\Php\SimpleXMLElementConstructorThrowTypeExtension
	{
		return new PHPStan\Type\Php\SimpleXMLElementConstructorThrowTypeExtension;
	}


	public function createService0288(): PHPStan\Type\Php\StatDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\StatDynamicReturnTypeExtension;
	}


	public function createService0289(): PHPStan\Type\Php\MethodExistsTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\MethodExistsTypeSpecifyingExtension;
	}


	public function createService0290(): PHPStan\Type\Php\PropertyExistsTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\PropertyExistsTypeSpecifyingExtension($this->getService('0180'));
	}


	public function createService0291(): PHPStan\Type\Php\MinMaxFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\MinMaxFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0292(): PHPStan\Type\Php\NumberFormatFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\NumberFormatFunctionDynamicReturnTypeExtension;
	}


	public function createService0293(): PHPStan\Type\Php\PathinfoFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\PathinfoFunctionDynamicReturnTypeExtension($this->getService('reflectionProvider'));
	}


	public function createService0294(): PHPStan\Type\Php\PregFilterFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\PregFilterFunctionReturnTypeExtension;
	}


	public function createService0295(): PHPStan\Type\Php\PregSplitDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\PregSplitDynamicReturnTypeExtension($this->getService('0188'));
	}


	public function createService0296(): PHPStan\Type\Php\ReflectionClassIsSubclassOfTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\ReflectionClassIsSubclassOfTypeSpecifyingExtension;
	}


	public function createService0297(): PHPStan\Type\Php\ReplaceFunctionsDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ReplaceFunctionsDynamicReturnTypeExtension;
	}


	public function createService0298(): PHPStan\Type\Php\ArrayPointerFunctionsDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ArrayPointerFunctionsDynamicReturnTypeExtension;
	}


	public function createService0299(): PHPStan\Type\Php\LtrimFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\LtrimFunctionReturnTypeExtension;
	}


	public function createService0300(): PHPStan\Type\Php\MbFunctionsReturnTypeExtension
	{
		return new PHPStan\Type\Php\MbFunctionsReturnTypeExtension($this->getService('026'));
	}


	public function createService0301(): PHPStan\Type\Php\MbConvertEncodingFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\MbConvertEncodingFunctionReturnTypeExtension;
	}


	public function createService0302(): PHPStan\Type\Php\MbSubstituteCharacterDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\MbSubstituteCharacterDynamicReturnTypeExtension($this->getService('026'));
	}


	public function createService0303(): PHPStan\Type\Php\MbStrlenFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\MbStrlenFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0304(): PHPStan\Type\Php\MicrotimeFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\MicrotimeFunctionReturnTypeExtension;
	}


	public function createService0305(): PHPStan\Type\Php\HrtimeFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\HrtimeFunctionReturnTypeExtension;
	}


	public function createService0306(): PHPStan\Type\Php\ImplodeFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ImplodeFunctionReturnTypeExtension;
	}


	public function createService0307(): PHPStan\Type\Php\NonEmptyStringFunctionsReturnTypeExtension
	{
		return new PHPStan\Type\Php\NonEmptyStringFunctionsReturnTypeExtension;
	}


	public function createService0308(): PHPStan\Type\Php\SetTypeFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\SetTypeFunctionTypeSpecifyingExtension;
	}


	public function createService0309(): PHPStan\Type\Php\StrCaseFunctionsReturnTypeExtension
	{
		return new PHPStan\Type\Php\StrCaseFunctionsReturnTypeExtension;
	}


	public function createService0310(): PHPStan\Type\Php\StrlenFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\StrlenFunctionReturnTypeExtension;
	}


	public function createService0311(): PHPStan\Type\Php\StrIncrementDecrementFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\StrIncrementDecrementFunctionReturnTypeExtension;
	}


	public function createService0312(): PHPStan\Type\Php\StrPadFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\StrPadFunctionReturnTypeExtension;
	}


	public function createService0313(): PHPStan\Type\Php\StrRepeatFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\StrRepeatFunctionReturnTypeExtension;
	}


	public function createService0314(): PHPStan\Type\Php\StrrevFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\StrrevFunctionReturnTypeExtension;
	}


	public function createService0315(): PHPStan\Type\Php\SubstrDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\SubstrDynamicReturnTypeExtension($this->getService('026'));
	}


	public function createService0316(): PHPStan\Type\Php\ThrowableReturnTypeExtension
	{
		return new PHPStan\Type\Php\ThrowableReturnTypeExtension;
	}


	public function createService0317(): PHPStan\Type\Php\ParseUrlFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\ParseUrlFunctionDynamicReturnTypeExtension;
	}


	public function createService0318(): PHPStan\Type\Php\TriggerErrorDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\TriggerErrorDynamicReturnTypeExtension($this->getService('026'));
	}


	public function createService0319(): PHPStan\Type\Php\TrimFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\TrimFunctionDynamicReturnTypeExtension;
	}


	public function createService0320(): PHPStan\Type\Php\VersionCompareFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\VersionCompareFunctionDynamicReturnTypeExtension(null, $this->getService('029'));
	}


	public function createService0321(): PHPStan\Type\Php\PowFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\PowFunctionReturnTypeExtension;
	}


	public function createService0322(): PHPStan\Type\Php\RoundFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\RoundFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0323(): PHPStan\Type\Php\StrtotimeFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\StrtotimeFunctionReturnTypeExtension;
	}


	public function createService0324(): PHPStan\Type\Php\RandomIntFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\RandomIntFunctionReturnTypeExtension;
	}


	public function createService0325(): PHPStan\Type\Php\RangeFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\RangeFunctionReturnTypeExtension;
	}


	public function createService0326(): PHPStan\Type\Php\AssertFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\AssertFunctionTypeSpecifyingExtension;
	}


	public function createService0327(): PHPStan\Type\Php\ClassExistsFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\ClassExistsFunctionTypeSpecifyingExtension;
	}


	public function createService0328(): PHPStan\Type\Php\ClassImplementsFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\ClassImplementsFunctionReturnTypeExtension;
	}


	public function createService0329(): PHPStan\Type\Php\DefineConstantTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\DefineConstantTypeSpecifyingExtension;
	}


	public function createService0330(): PHPStan\Type\Php\DefinedConstantTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\DefinedConstantTypeSpecifyingExtension($this->getService('0234'));
	}


	public function createService0331(): PHPStan\Type\Php\FunctionExistsFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\FunctionExistsFunctionTypeSpecifyingExtension;
	}


	public function createService0332(): PHPStan\Type\Php\InArrayFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\InArrayFunctionTypeSpecifyingExtension;
	}


	public function createService0333(): PHPStan\Type\Php\IsArrayFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\IsArrayFunctionTypeSpecifyingExtension;
	}


	public function createService0334(): PHPStan\Type\Php\IsCallableFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\IsCallableFunctionTypeSpecifyingExtension($this->getService('0289'));
	}


	public function createService0335(): PHPStan\Type\Php\IsIterableFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\IsIterableFunctionTypeSpecifyingExtension;
	}


	public function createService0336(): PHPStan\Type\Php\IsSubclassOfFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\IsSubclassOfFunctionTypeSpecifyingExtension($this->getService('0339'));
	}


	public function createService0337(): PHPStan\Type\Php\IteratorToArrayFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\IteratorToArrayFunctionReturnTypeExtension;
	}


	public function createService0338(): PHPStan\Type\Php\IsAFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\IsAFunctionTypeSpecifyingExtension($this->getService('0339'));
	}


	public function createService0339(): PHPStan\Type\Php\IsAFunctionTypeSpecifyingHelper
	{
		return new PHPStan\Type\Php\IsAFunctionTypeSpecifyingHelper;
	}


	public function createService0340(): PHPStan\Type\Php\CtypeDigitFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\Php\CtypeDigitFunctionTypeSpecifyingExtension;
	}


	public function createService0341(): PHPStan\Type\Php\JsonThrowOnErrorDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\JsonThrowOnErrorDynamicReturnTypeExtension(
			$this->getService('reflectionProvider'),
			$this->getService('0188')
		);
	}


	public function createService0342(): PHPStan\Type\Php\TypeSpecifyingFunctionsDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\TypeSpecifyingFunctionsDynamicReturnTypeExtension(
			$this->getService('reflectionProvider'),
			true,
			['stdClass']
		);
	}


	public function createService0343(): PHPStan\Type\Php\SimpleXMLElementAsXMLMethodReturnTypeExtension
	{
		return new PHPStan\Type\Php\SimpleXMLElementAsXMLMethodReturnTypeExtension;
	}


	public function createService0344(): PHPStan\Type\Php\SimpleXMLElementXpathMethodReturnTypeExtension
	{
		return new PHPStan\Type\Php\SimpleXMLElementXpathMethodReturnTypeExtension;
	}


	public function createService0345(): PHPStan\Type\Php\StrSplitFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\StrSplitFunctionReturnTypeExtension($this->getService('026'));
	}


	public function createService0346(): PHPStan\Type\Php\StrTokFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\StrTokFunctionReturnTypeExtension;
	}


	public function createService0347(): PHPStan\Type\Php\SprintfFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\SprintfFunctionDynamicReturnTypeExtension;
	}


	public function createService0348(): PHPStan\Type\Php\SscanfFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\SscanfFunctionDynamicReturnTypeExtension;
	}


	public function createService0349(): PHPStan\Type\Php\StrvalFamilyFunctionReturnTypeExtension
	{
		return new PHPStan\Type\Php\StrvalFamilyFunctionReturnTypeExtension;
	}


	public function createService0350(): PHPStan\Type\Php\StrWordCountFunctionDynamicReturnTypeExtension
	{
		return new PHPStan\Type\Php\StrWordCountFunctionDynamicReturnTypeExtension;
	}


	public function createService0351(): PHPStan\Type\Php\XMLReaderOpenReturnTypeExtension
	{
		return new PHPStan\Type\Php\XMLReaderOpenReturnTypeExtension;
	}


	public function createService0352(): PHPStan\Type\Php\ReflectionGetAttributesMethodReturnTypeExtension
	{
		return new PHPStan\Type\Php\ReflectionGetAttributesMethodReturnTypeExtension('ReflectionClass');
	}


	public function createService0353(): PHPStan\Type\Php\ReflectionGetAttributesMethodReturnTypeExtension
	{
		return new PHPStan\Type\Php\ReflectionGetAttributesMethodReturnTypeExtension('ReflectionClassConstant');
	}


	public function createService0354(): PHPStan\Type\Php\ReflectionGetAttributesMethodReturnTypeExtension
	{
		return new PHPStan\Type\Php\ReflectionGetAttributesMethodReturnTypeExtension('ReflectionFunctionAbstract');
	}


	public function createService0355(): PHPStan\Type\Php\ReflectionGetAttributesMethodReturnTypeExtension
	{
		return new PHPStan\Type\Php\ReflectionGetAttributesMethodReturnTypeExtension('ReflectionParameter');
	}


	public function createService0356(): PHPStan\Type\Php\ReflectionGetAttributesMethodReturnTypeExtension
	{
		return new PHPStan\Type\Php\ReflectionGetAttributesMethodReturnTypeExtension('ReflectionProperty');
	}


	public function createService0357(): PHPStan\Type\Php\DatePeriodConstructorReturnTypeExtension
	{
		return new PHPStan\Type\Php\DatePeriodConstructorReturnTypeExtension;
	}


	public function createService0358(): PHPStan\Type\PHPStan\ClassNameUsageLocationCreateIdentifierDynamicReturnTypeExtension
	{
		return new PHPStan\Type\PHPStan\ClassNameUsageLocationCreateIdentifierDynamicReturnTypeExtension;
	}


	public function createService0359(): PHPStan\Type\ClosureTypeFactory
	{
		return new PHPStan\Type\ClosureTypeFactory(
			$this->getService('096'),
			$this->getService('0366'),
			$this->getService('originalBetterReflectionReflector'),
			$this->getService('currentPhpVersionPhpParser')
		);
	}


	public function createService0360(): PHPStan\Type\Constant\OversizedArrayBuilder
	{
		return new PHPStan\Type\Constant\OversizedArrayBuilder;
	}


	public function createService0361(): PHPStan\Rules\Functions\PrintfHelper
	{
		return new PHPStan\Rules\Functions\PrintfHelper($this->getService('026'));
	}


	public function createService0362(): PHPStan\Reflection\BetterReflection\BetterReflectionSourceLocatorFactory
	{
		return new PHPStan\Reflection\BetterReflection\BetterReflectionSourceLocatorFactory(
			$this->getService('phpParserDecorator'),
			$this->getService('php8PhpParser'),
			$this->getService('0365'),
			$this->getService('0366'),
			$this->getService('0106'),
			$this->getService('0103'),
			$this->getService('0101'),
			$this->getService('0104'),
			$this->getService('0100'),
			[
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/stubs/Twig/functions.stub',
			],
			[],
			$this->getParameter('analysedPaths'),
			['/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal'],
			$this->getParameter('analysedPathsFromConfig'),
			false,
			$this->getParameter('singleReflectionFile')
		);
	}


	public function createService0363(): PHPStan\Reflection\BetterReflection\BetterReflectionProviderFactory
	{
		return new class ($this) implements PHPStan\Reflection\BetterReflection\BetterReflectionProviderFactory {
			private $container;


			public function __construct(Container_b4e34e1e86 $container)
			{
				$this->container = $container;
			}


			public function create(PHPStan\BetterReflection\Reflector\Reflector $reflector): PHPStan\Reflection\BetterReflection\BetterReflectionProvider
			{
				return new PHPStan\Reflection\BetterReflection\BetterReflectionProvider(
					$this->container->getService('0122'),
					$this->container->getService('096'),
					$this->container->getService('078'),
					$reflector,
					$this->container->getService('0185'),
					$this->container->getService('036'),
					$this->container->getService('0368'),
					$this->container->getService('026'),
					$this->container->getService('0123'),
					$this->container->getService('stubPhpDocProvider'),
					$this->container->getService('095'),
					$this->container->getService('relativePathHelper'),
					$this->container->getService('025'),
					$this->container->getService('085'),
					$this->container->getService('0365'),
					$this->container->getService('0128'),
					$this->container->getService('094'),
					['stdClass']
				);
			}
		};
	}


	public function createService0364(): PHPStan\Reflection\BetterReflection\SourceStubber\PhpStormStubsSourceStubberFactory
	{
		return new PHPStan\Reflection\BetterReflection\SourceStubber\PhpStormStubsSourceStubberFactory(
			$this->getService('php8PhpParser'),
			$this->getService('024'),
			$this->getService('026')
		);
	}


	public function createService0365(): PHPStan\BetterReflection\SourceLocator\SourceStubber\PhpStormStubsSourceStubber
	{
		return $this->getService('0364')->create();
	}


	public function createService0366(): PHPStan\BetterReflection\SourceLocator\SourceStubber\ReflectionSourceStubber
	{
		return $this->getService('0367')->create();
	}


	public function createService0367(): PHPStan\Reflection\BetterReflection\SourceStubber\ReflectionSourceStubberFactory
	{
		return new PHPStan\Reflection\BetterReflection\SourceStubber\ReflectionSourceStubberFactory(
			$this->getService('024'),
			$this->getService('026')
		);
	}


	public function createService0368(): PHPStan\Reflection\Deprecation\DeprecationProvider
	{
		return new PHPStan\Reflection\Deprecation\DeprecationProvider($this->getService('075'));
	}


	public function createService0369(): PHPStan\Command\ErrorFormatter\CiDetectedErrorFormatter
	{
		return new PHPStan\Command\ErrorFormatter\CiDetectedErrorFormatter(
			$this->getService('errorFormatter.github'),
			$this->getService('errorFormatter.teamcity')
		);
	}


	public function createService0370(): PHPStan\Rules\Classes\ExistingClassInClassExtendsRule
	{
		return new PHPStan\Rules\Classes\ExistingClassInClassExtendsRule(
			$this->getService('0132'),
			$this->getService('reflectionProvider'),
			true
		);
	}


	public function createService0371(): PHPStan\Rules\Classes\ExistingClassesInClassImplementsRule
	{
		return new PHPStan\Rules\Classes\ExistingClassesInClassImplementsRule(
			$this->getService('0132'),
			$this->getService('reflectionProvider'),
			true
		);
	}


	public function createService0372(): PHPStan\Rules\Classes\ExistingClassesInEnumImplementsRule
	{
		return new PHPStan\Rules\Classes\ExistingClassesInEnumImplementsRule(
			$this->getService('0132'),
			$this->getService('reflectionProvider'),
			true
		);
	}


	public function createService0373(): PHPStan\Rules\Classes\ExistingClassInInstanceOfRule
	{
		return new PHPStan\Rules\Classes\ExistingClassInInstanceOfRule(
			$this->getService('reflectionProvider'),
			$this->getService('0132'),
			false,
			true
		);
	}


	public function createService0374(): PHPStan\Rules\Classes\ExistingClassesInInterfaceExtendsRule
	{
		return new PHPStan\Rules\Classes\ExistingClassesInInterfaceExtendsRule(
			$this->getService('0132'),
			$this->getService('reflectionProvider'),
			true
		);
	}


	public function createService0375(): PHPStan\Rules\Classes\ExistingClassInTraitUseRule
	{
		return new PHPStan\Rules\Classes\ExistingClassInTraitUseRule(
			$this->getService('0132'),
			$this->getService('reflectionProvider'),
			true
		);
	}


	public function createService0376(): PHPStan\Rules\Classes\InstantiationRule
	{
		return new PHPStan\Rules\Classes\InstantiationRule(
			$this->getService('075'),
			$this->getService('reflectionProvider'),
			$this->getService('0147'),
			$this->getService('0132'),
			true
		);
	}


	public function createService0377(): PHPStan\Rules\Exceptions\CaughtExceptionExistenceRule
	{
		return new PHPStan\Rules\Exceptions\CaughtExceptionExistenceRule(
			$this->getService('reflectionProvider'),
			$this->getService('0132'),
			false,
			true
		);
	}


	public function createService0378(): PHPStan\Rules\Functions\CallToNonExistentFunctionRule
	{
		return new PHPStan\Rules\Functions\CallToNonExistentFunctionRule($this->getService('reflectionProvider'), false, true);
	}


	public function createService0379(): PHPStan\Rules\Classes\NewStaticInAbstractClassStaticMethodRule
	{
		return new PHPStan\Rules\Classes\NewStaticInAbstractClassStaticMethodRule;
	}


	public function createService0380(): PHPStan\Rules\Constants\OverridingConstantRule
	{
		return new PHPStan\Rules\Constants\OverridingConstantRule(false);
	}


	public function createService0381(): PHPStan\Rules\Methods\OverridingMethodRule
	{
		return new PHPStan\Rules\Methods\OverridingMethodRule(
			$this->getService('026'),
			$this->getService('0161'),
			false,
			$this->getService('0162'),
			$this->getService('0163'),
			$this->getService('0115'),
			false
		);
	}


	public function createService0382(): PHPStan\Rules\Missing\MissingReturnRule
	{
		return new PHPStan\Rules\Missing\MissingReturnRule(false, false);
	}


	public function createService0383(): PHPStan\Rules\Namespaces\ExistingNamesInGroupUseRule
	{
		return new PHPStan\Rules\Namespaces\ExistingNamesInGroupUseRule(
			$this->getService('reflectionProvider'),
			$this->getService('0132'),
			false,
			true
		);
	}


	public function createService0384(): PHPStan\Rules\Namespaces\ExistingNamesInUseRule
	{
		return new PHPStan\Rules\Namespaces\ExistingNamesInUseRule(
			$this->getService('reflectionProvider'),
			$this->getService('0132'),
			false,
			true
		);
	}


	public function createService0385(): PHPStan\Rules\Properties\AccessPropertiesRule
	{
		return new PHPStan\Rules\Properties\AccessPropertiesRule($this->getService('0175'));
	}


	public function createService0386(): PHPStan\Rules\Properties\AccessStaticPropertiesRule
	{
		return new PHPStan\Rules\Properties\AccessStaticPropertiesRule(
			$this->getService('reflectionProvider'),
			$this->getService('0182'),
			$this->getService('0132'),
			true
		);
	}


	public function createService0387(): PHPStan\Rules\Properties\ExistingClassesInPropertiesRule
	{
		return new PHPStan\Rules\Properties\ExistingClassesInPropertiesRule(
			$this->getService('reflectionProvider'),
			$this->getService('0132'),
			$this->getService('0170'),
			$this->getService('026'),
			false,
			true,
			true
		);
	}


	public function createService0388(): PHPStan\Rules\Functions\FunctionCallableRule
	{
		return new PHPStan\Rules\Functions\FunctionCallableRule(
			$this->getService('reflectionProvider'),
			$this->getService('0182'),
			$this->getService('026'),
			false,
			false
		);
	}


	public function createService0389(): PHPStan\Rules\Properties\OverridingPropertyRule
	{
		return new PHPStan\Rules\Properties\OverridingPropertyRule($this->getService('026'), false, false);
	}


	public function createService0390(): PHPStan\Rules\Properties\SetPropertyHookParameterRule
	{
		return new PHPStan\Rules\Properties\SetPropertyHookParameterRule($this->getService('0164'), false, false);
	}


	public function createService0391(): PHPStan\Rules\Properties\WritingToReadOnlyPropertiesRule
	{
		return new PHPStan\Rules\Properties\WritingToReadOnlyPropertiesRule(
			$this->getService('0182'),
			$this->getService('0179'),
			$this->getService('0180'),
			true
		);
	}


	public function createService0392(): PHPStan\Rules\Properties\ReadingWriteOnlyPropertiesRule
	{
		return new PHPStan\Rules\Properties\ReadingWriteOnlyPropertiesRule(
			$this->getService('0179'),
			$this->getService('0180'),
			$this->getService('0182'),
			true
		);
	}


	public function createService0393(): PHPStan\Rules\Variables\CompactVariablesRule
	{
		return new PHPStan\Rules\Variables\CompactVariablesRule(false);
	}


	public function createService0394(): PHPStan\Rules\Variables\DefinedVariableRule
	{
		return new PHPStan\Rules\Variables\DefinedVariableRule(true, false);
	}


	public function createService0395(): PHPStan\Rules\Keywords\RequireFileExistsRule
	{
		return new PHPStan\Rules\Keywords\RequireFileExistsRule('/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal');
	}


	public function createService0396(): PHPStan\Rules\InternalTag\RestrictedInternalClassConstantUsageExtension
	{
		return new PHPStan\Rules\InternalTag\RestrictedInternalClassConstantUsageExtension($this->getService('0157'));
	}


	public function createService0397(): PHPStan\Rules\InternalTag\RestrictedInternalClassNameUsageExtension
	{
		return new PHPStan\Rules\InternalTag\RestrictedInternalClassNameUsageExtension($this->getService('0157'));
	}


	public function createService0398(): PHPStan\Rules\InternalTag\RestrictedInternalFunctionUsageExtension
	{
		return new PHPStan\Rules\InternalTag\RestrictedInternalFunctionUsageExtension($this->getService('0157'));
	}


	public function createService0399(): Composer\PHPStan\ConfigReturnTypeExtension
	{
		return new Composer\PHPStan\ConfigReturnTypeExtension;
	}


	public function createService0400(): Composer\PHPStan\RuleReasonDataReturnTypeExtension
	{
		return new Composer\PHPStan\RuleReasonDataReturnTypeExtension;
	}


	public function createService0401(): Composer\Pcre\PHPStan\PregMatchParameterOutTypeExtension
	{
		return new Composer\Pcre\PHPStan\PregMatchParameterOutTypeExtension($this->getService('0278'));
	}


	public function createService0402(): Composer\Pcre\PHPStan\PregMatchTypeSpecifyingExtension
	{
		return new Composer\Pcre\PHPStan\PregMatchTypeSpecifyingExtension($this->getService('0278'));
	}


	public function createService0403(): Composer\Pcre\PHPStan\PregReplaceCallbackClosureTypeExtension
	{
		return new Composer\Pcre\PHPStan\PregReplaceCallbackClosureTypeExtension($this->getService('0278'));
	}


	public function createService0404(): mglaman\PHPStanDrupal\Drupal\ServiceMap
	{
		return new mglaman\PHPStanDrupal\Drupal\ServiceMap;
	}


	public function createService0405(): mglaman\PHPStanDrupal\Drupal\ExtensionMap
	{
		return new mglaman\PHPStanDrupal\Drupal\ExtensionMap;
	}


	public function createService0406(): mglaman\PHPStanDrupal\Drupal\EntityDataRepository
	{
		return new mglaman\PHPStanDrupal\Drupal\EntityDataRepository([
			'aggregator_feed' => ['class' => 'Drupal\aggregator\Entity\Feed', 'storage' => 'Drupal\aggregator\FeedStorage'],
			'aggregator_item' => ['class' => 'Drupal\aggregator\Entity\Item', 'storage' => 'Drupal\aggregator\ItemStorage'],
			'block' => ['class' => 'Drupal\block\Entity\Block', 'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage'],
			'block_content' => [
				'class' => 'Drupal\block_content\Entity\BlockContent',
				'storage' => 'Drupal\Core\Entity\Sql\SqlContentEntityStorage',
			],
			'block_content_type' => [
				'class' => 'Drupal\block_content\Entity\BlockContentType',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'comment_type' => [
				'class' => 'Drupal\comment\Entity\CommentType',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'comment' => ['class' => 'Drupal\comment\Entity\Comment', 'storage' => 'Drupal\comment\CommentStorage'],
			'contact_form' => [
				'class' => 'Drupal\contact\Entity\ContactForm',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'contact_message' => [
				'class' => 'Drupal\contact\Entity\Message',
				'storage' => 'Drupal\Core\Entity\ContentEntityNullStorage',
			],
			'content_moderation_state' => [
				'class' => 'Drupal\content_moderation\Entity\ContentModerationState',
				'storage' => 'Drupal\Core\Entity\Sql\SqlContentEntityStorage',
			],
			'editor' => [
				'class' => 'Drupal\editor\Entity\Editor',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'field_config' => ['class' => 'Drupal\field\Entity\FieldConfig', 'storage' => 'Drupal\field\FieldConfigStorage'],
			'field_storage_config' => [
				'class' => 'Drupal\field\Entity\FieldStorageConfig',
				'storage' => 'Drupal\field\FieldStorageConfigStorage',
			],
			'file' => ['class' => 'Drupal\file\Entity\File', 'storage' => 'Drupal\file\FileStorage'],
			'filter_format' => [
				'class' => 'Drupal\filter\Entity\FilterFormat',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'image_style' => ['class' => 'Drupal\image\Entity\ImageStyle', 'storage' => 'Drupal\image\ImageStyleStorage'],
			'imce_profile' => [
				'class' => 'Drupal\imce\Entity\ImceProfile',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'configurable_language' => [
				'class' => 'Drupal\language\Entity\ConfigurableLanguage',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'language_content_settings' => [
				'class' => 'Drupal\language\Entity\ContentLanguageSettings',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'media_type' => [
				'class' => 'Drupal\media\Entity\MediaType',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'media' => ['class' => 'Drupal\media\Entity\Media', 'storage' => 'Drupal\media\MediaStorage'],
			'menu_link_content' => [
				'class' => 'Drupal\menu_link_content\Entity\MenuLinkContent',
				'storage' => '\Drupal\menu_link_content\MenuLinkContentStorage',
			],
			'metatag_defaults' => [
				'class' => 'Drupal\metatag\Entity\MetatagDefaults',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'node_type' => [
				'class' => 'Drupal\node\Entity\NodeType',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'node' => ['class' => 'Drupal\node\Entity\Node', 'storage' => 'Drupal\node\NodeStorage'],
			'path_alias' => [
				'class' => 'Drupal\path_alias\Entity\PathAlias',
				'storage' => 'Drupal\path_alias\PathAliasStorage',
			],
			'rdf_mapping' => [
				'class' => 'Drupal\rdf\Entity\RdfMapping',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'responsive_image_style' => [
				'class' => 'Drupal\responsive_image\Entity\ResponsiveImageStyle',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'search_page' => [
				'class' => 'Drupal\search\Entity\SearchPage',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'search_api_server' => [
				'class' => 'Drupal\search_api\Entity\Server',
				'storage' => 'Drupal\search_api\Entity\SearchApiConfigEntityStorage',
			],
			'search_api_index' => [
				'class' => 'Drupal\search_api\Entity\Index',
				'storage' => 'Drupal\search_api\Entity\SearchApiConfigEntityStorage',
			],
			'search_api_task' => [
				'class' => 'Drupal\search_api\Entity\Task',
				'storage' => 'Drupal\Core\Entity\Sql\SqlContentEntityStorage',
			],
			'shortcut_set' => [
				'class' => 'Drupal\shortcut\Entity\ShortcutSet',
				'storage' => 'Drupal\shortcut\ShortcutSetStorage',
			],
			'shortcut' => [
				'class' => 'Drupal\shortcut\Entity\Shortcut',
				'storage' => 'Drupal\Core\Entity\Sql\SqlContentEntityStorage',
			],
			'action' => [
				'class' => 'Drupal\system\Entity\Action',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'menu' => ['class' => 'Drupal\system\Entity\Menu', 'storage' => 'Drupal\system\MenuStorage'],
			'taxonomy_term' => ['class' => 'Drupal\taxonomy\Entity\Term', 'storage' => 'Drupal\taxonomy\TermStorage'],
			'taxonomy_vocabulary' => [
				'class' => 'Drupal\taxonomy\Entity\Vocabulary',
				'storage' => 'Drupal\taxonomy\VocabularyStorage',
			],
			'tour' => ['class' => 'Drupal\tour\Entity\Tour', 'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage'],
			'user' => ['class' => 'Drupal\user\Entity\User', 'storage' => 'Drupal\user\UserStorage'],
			'user_role' => ['class' => 'Drupal\user\Entity\Role', 'storage' => 'Drupal\user\RoleStorage'],
			'webform' => ['class' => 'Drupal\webform\Entity\Webform', 'storage' => '\Drupal\webform\WebformEntityStorage'],
			'webform_submission' => [
				'class' => 'Drupal\webform\Entity\WebformSubmission',
				'storage' => 'Drupal\webform\WebformSubmissionStorage',
			],
			'webform_options' => [
				'class' => 'Drupal\webform\Entity\WebformOptions',
				'storage' => '\Drupal\webform\WebformOptionsStorage',
			],
			'workflow' => [
				'class' => 'Drupal\workflows\Entity\Workflow',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'pathauto_pattern' => [
				'class' => 'Drupal\pathauto\Entity\PathautoPattern',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'view' => ['class' => 'Drupal\views\Entity\View', 'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage'],
			'date_format' => [
				'class' => 'Drupal\Core\Datetime\Entity\DateFormat',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'entity_form_mode' => [
				'class' => 'Drupal\Core\Entity\Entity\EntityFormMode',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'entity_view_display' => [
				'class' => 'Drupal\layout_builder\Entity\LayoutBuilderEntityViewDisplay',
				'storage' => 'Drupal\layout_builder\Entity\LayoutBuilderEntityViewDisplayStorage',
			],
			'entity_form_display' => [
				'class' => 'Drupal\Core\Entity\Entity\EntityFormDisplay',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'entity_view_mode' => [
				'class' => 'Drupal\Core\Entity\Entity\EntityViewMode',
				'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
			],
			'base_field_override' => [
				'class' => 'Drupal\Core\Field\Entity\BaseFieldOverride',
				'storage' => 'Drupal\Core\Field\BaseFieldOverrideStorage',
			],
		]);
	}


	public function createService0407(): mglaman\PHPStanDrupal\Type\EntityTypeManagerGetStorageDynamicReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\EntityTypeManagerGetStorageDynamicReturnTypeExtension($this->getService('0406'));
	}


	public function createService0408(): mglaman\PHPStanDrupal\Type\EntityStorage\EntityStorageDynamicReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\EntityStorage\EntityStorageDynamicReturnTypeExtension($this->getService('0406'));
	}


	public function createService0409(): mglaman\PHPStanDrupal\Type\EntityRepositoryReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\EntityRepositoryReturnTypeExtension($this->getService('0406'));
	}


	public function createService0410(): mglaman\PHPStanDrupal\Type\EntityStorage\GetQueryReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\EntityStorage\GetQueryReturnTypeExtension;
	}


	public function createService0411(): mglaman\PHPStanDrupal\Type\ContainerDynamicReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\ContainerDynamicReturnTypeExtension($this->getService('0404'));
	}


	public function createService0412(): mglaman\PHPStanDrupal\Type\DrupalClassResolverDynamicReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\DrupalClassResolverDynamicReturnTypeExtension($this->getService('0404'));
	}


	public function createService0413(): mglaman\PHPStanDrupal\Type\EntityQuery\EntityQueryDynamicReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\EntityQuery\EntityQueryDynamicReturnTypeExtension;
	}


	public function createService0414(): mglaman\PHPStanDrupal\Type\EntityQuery\EntityQueryAccessCheckDynamicReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\EntityQuery\EntityQueryAccessCheckDynamicReturnTypeExtension;
	}


	public function createService0415(): mglaman\PHPStanDrupal\Type\EntityAccessControlHandlerReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\EntityAccessControlHandlerReturnTypeExtension;
	}


	public function createService0416(): mglaman\PHPStanDrupal\Type\DrupalClassResolverDynamicStaticReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\DrupalClassResolverDynamicStaticReturnTypeExtension($this->getService('0404'));
	}


	public function createService0417(): mglaman\PHPStanDrupal\Type\DrupalServiceDynamicReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\DrupalServiceDynamicReturnTypeExtension($this->getService('0404'));
	}


	public function createService0418(): mglaman\PHPStanDrupal\Type\DrupalStaticEntityQueryDynamicReturnTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\DrupalStaticEntityQueryDynamicReturnTypeExtension($this->getService('0406'));
	}


	public function createService0419(): mglaman\PHPStanDrupal\Reflection\EntityFieldsViaMagicReflectionExtension
	{
		return new mglaman\PHPStanDrupal\Reflection\EntityFieldsViaMagicReflectionExtension($this->getService('reflectionProvider'));
	}


	public function createService0420(): mglaman\PHPStanDrupal\Reflection\EntityFieldMethodsViaMagicReflectionExtension
	{
		return new mglaman\PHPStanDrupal\Reflection\EntityFieldMethodsViaMagicReflectionExtension;
	}


	public function createService0421(): mglaman\PHPStanDrupal\Drupal\DrupalStubFilesExtension
	{
		return new mglaman\PHPStanDrupal\Drupal\DrupalStubFilesExtension;
	}


	public function createService0422(): mglaman\PHPStanDrupal\Type\EntityQuery\AccessCheckTypeSpecifyingExtension
	{
		return new mglaman\PHPStanDrupal\Type\EntityQuery\AccessCheckTypeSpecifyingExtension;
	}


	public function createService0423(): mglaman\PHPStanDrupal\DeprecatedScope\GroupLegacyScope
	{
		return new mglaman\PHPStanDrupal\DeprecatedScope\GroupLegacyScope;
	}


	public function createService0424(): mglaman\PHPStanDrupal\DeprecatedScope\IgnoreDeprecationsScope
	{
		return new mglaman\PHPStanDrupal\DeprecatedScope\IgnoreDeprecationsScope;
	}


	public function createService0425(): mglaman\PHPStanDrupal\DeprecatedScope\DeprecationHelperScope
	{
		return new mglaman\PHPStanDrupal\DeprecatedScope\DeprecationHelperScope;
	}


	public function createService0426(): mglaman\PHPStanDrupal\Type\InspectorTypeExtension
	{
		return new mglaman\PHPStanDrupal\Type\InspectorTypeExtension;
	}


	public function createService0427(): mglaman\PHPStanDrupal\Rules\Drupal\Tests\TestClassSuffixNameRule
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\Tests\TestClassSuffixNameRule;
	}


	public function createService0428(): mglaman\PHPStanDrupal\Rules\Drupal\DependencySerializationTraitPropertyRule
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\DependencySerializationTraitPropertyRule;
	}


	public function createService0429(): mglaman\PHPStanDrupal\Rules\Drupal\AccessResultConditionRule
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\AccessResultConditionRule(true);
	}


	public function createService0430(): mglaman\PHPStanDrupal\Rules\Classes\ClassExtendsInternalClassRule
	{
		return new mglaman\PHPStanDrupal\Rules\Classes\ClassExtendsInternalClassRule($this->getService('reflectionProvider'));
	}


	public function createService0431(): mglaman\PHPStanDrupal\Rules\Classes\PluginManagerInspectionRule
	{
		return new mglaman\PHPStanDrupal\Rules\Classes\PluginManagerInspectionRule($this->getService('reflectionProvider'));
	}


	public function createService0432(): PHPStan\DependencyInjection\LazyDeprecatedScopeResolverProvider
	{
		return new PHPStan\DependencyInjection\LazyDeprecatedScopeResolverProvider($this->getService('075'));
	}


	public function createService0433(): PHPStan\Rules\Deprecations\DeprecatedScopeHelper
	{
		return $this->getService('0432')->get();
	}


	public function createService0434(): PHPStan\Rules\Deprecations\DefaultDeprecatedScopeResolver
	{
		return new PHPStan\Rules\Deprecations\DefaultDeprecatedScopeResolver;
	}


	public function createService0435(): PHPStan\Rules\Deprecations\CallWithDeprecatedIniOptionRule
	{
		return new PHPStan\Rules\Deprecations\CallWithDeprecatedIniOptionRule(
			$this->getService('reflectionProvider'),
			$this->getService('0433'),
			$this->getService('026')
		);
	}


	public function createService0436(): PHPStan\Rules\Deprecations\RestrictedDeprecatedClassConstantUsageExtension
	{
		return new PHPStan\Rules\Deprecations\RestrictedDeprecatedClassConstantUsageExtension($this->getService('0433'));
	}


	public function createService0437(): PHPStan\Rules\Deprecations\RestrictedDeprecatedFunctionUsageExtension
	{
		return new PHPStan\Rules\Deprecations\RestrictedDeprecatedFunctionUsageExtension($this->getService('0433'));
	}


	public function createService0438(): PHPStan\Rules\Deprecations\RestrictedDeprecatedMethodUsageExtension
	{
		return new PHPStan\Rules\Deprecations\RestrictedDeprecatedMethodUsageExtension($this->getService('0433'));
	}


	public function createService0439(): PHPStan\Rules\Deprecations\RestrictedDeprecatedPropertyUsageExtension
	{
		return new PHPStan\Rules\Deprecations\RestrictedDeprecatedPropertyUsageExtension($this->getService('0433'));
	}


	public function createService0440(): PHPStan\Rules\Deprecations\RestrictedDeprecatedClassNameUsageExtension
	{
		return new PHPStan\Rules\Deprecations\RestrictedDeprecatedClassNameUsageExtension(
			$this->getService('0433'),
			$this->getService('reflectionProvider'),
			false
		);
	}


	public function createService0441(): PHPStan\PhpDoc\PHPUnit\MockObjectTypeNodeResolverExtension
	{
		return new PHPStan\PhpDoc\PHPUnit\MockObjectTypeNodeResolverExtension;
	}


	public function createService0442(): PHPStan\Type\PHPUnit\Assert\AssertFunctionTypeSpecifyingExtension
	{
		return new PHPStan\Type\PHPUnit\Assert\AssertFunctionTypeSpecifyingExtension;
	}


	public function createService0443(): PHPStan\Type\PHPUnit\Assert\AssertMethodTypeSpecifyingExtension
	{
		return new PHPStan\Type\PHPUnit\Assert\AssertMethodTypeSpecifyingExtension;
	}


	public function createService0444(): PHPStan\Type\PHPUnit\Assert\AssertStaticMethodTypeSpecifyingExtension
	{
		return new PHPStan\Type\PHPUnit\Assert\AssertStaticMethodTypeSpecifyingExtension;
	}


	public function createService0445(): PHPStan\Type\PHPUnit\MockBuilderDynamicReturnTypeExtension
	{
		return new PHPStan\Type\PHPUnit\MockBuilderDynamicReturnTypeExtension;
	}


	public function createService0446(): PHPStan\Rules\PHPUnit\CoversHelper
	{
		return new PHPStan\Rules\PHPUnit\CoversHelper($this->getService('reflectionProvider'));
	}


	public function createService0447(): PHPStan\Rules\PHPUnit\AnnotationHelper
	{
		return new PHPStan\Rules\PHPUnit\AnnotationHelper;
	}


	public function createService0448(): PHPStan\Rules\PHPUnit\DataProviderHelper
	{
		return $this->getService('0449')->create();
	}


	public function createService0449(): PHPStan\Rules\PHPUnit\DataProviderHelperFactory
	{
		return new PHPStan\Rules\PHPUnit\DataProviderHelperFactory($this->getService('reflectionProvider'), $this->getService('0185'));
	}


	public function createService0450(): PHPStan\Rules\PHPUnit\DataProviderDeclarationRule
	{
		return new PHPStan\Rules\PHPUnit\DataProviderDeclarationRule($this->getService('0448'), false, true);
	}


	public function createService0451(): PHPStan\Rules\PHPUnit\AssertEqualsIsDiscouragedRule
	{
		return new PHPStan\Rules\PHPUnit\AssertEqualsIsDiscouragedRule;
	}


	public function createServiceBetterReflectionProvider(): PHPStan\Reflection\BetterReflection\BetterReflectionProvider
	{
		return new PHPStan\Reflection\BetterReflection\BetterReflectionProvider(
			$this->getService('0122'),
			$this->getService('096'),
			$this->getService('078'),
			$this->getService('betterReflectionReflector'),
			$this->getService('0185'),
			$this->getService('036'),
			$this->getService('0368'),
			$this->getService('026'),
			$this->getService('0123'),
			$this->getService('stubPhpDocProvider'),
			$this->getService('095'),
			$this->getService('relativePathHelper'),
			$this->getService('025'),
			$this->getService('085'),
			$this->getService('0365'),
			$this->getService('0128'),
			$this->getService('094'),
			['stdClass']
		);
	}


	public function createServiceBetterReflectionReflector(): PHPStan\Reflection\BetterReflection\Reflector\MemoizingReflector
	{
		return new PHPStan\Reflection\BetterReflection\Reflector\MemoizingReflector($this->getService('originalBetterReflectionReflector'));
	}


	public function createServiceBetterReflectionSourceLocator(): PHPStan\BetterReflection\SourceLocator\Type\SourceLocator
	{
		return $this->getService('0362')->create();
	}


	public function createServiceCacheStorage(): PHPStan\Cache\FileCacheStorage
	{
		return new PHPStan\Cache\FileCacheStorage('/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/var/phpstan/cache/PHPStan');
	}


	public function createServiceContainer(): Container_b4e34e1e86
	{
		return $this;
	}


	public function createServiceCurrentPhpVersionLexer(): PhpParser\Lexer
	{
		return $this->getService('02')->create();
	}


	public function createServiceCurrentPhpVersionPhpParser(): PhpParser\ParserAbstract
	{
		return $this->getService('currentPhpVersionPhpParserFactory')->create();
	}


	public function createServiceCurrentPhpVersionPhpParserFactory(): PHPStan\Parser\PhpParserFactory
	{
		return new PHPStan\Parser\PhpParserFactory($this->getService('currentPhpVersionLexer'), $this->getService('026'));
	}


	public function createServiceCurrentPhpVersionRichParser(): PHPStan\Parser\RichParser
	{
		return new PHPStan\Parser\RichParser(
			$this->getService('currentPhpVersionPhpParser'),
			$this->getService('03'),
			$this->getService('075'),
			$this->getService('056')
		);
	}


	public function createServiceCurrentPhpVersionSimpleDirectParser(): PHPStan\Parser\SimpleParser
	{
		return new PHPStan\Parser\SimpleParser(
			$this->getService('currentPhpVersionPhpParser'),
			$this->getService('03'),
			$this->getService('021'),
			$this->getService('022')
		);
	}


	public function createServiceCurrentPhpVersionSimpleParser(): PHPStan\Parser\CleaningParser
	{
		return new PHPStan\Parser\CleaningParser($this->getService('currentPhpVersionSimpleDirectParser'), $this->getService('026'));
	}


	public function createServiceDefaultAnalysisParser(): PHPStan\Parser\CachedParser
	{
		return new PHPStan\Parser\CachedParser($this->getService('pathRoutingParser'), 256);
	}


	public function createServiceErrorFormatter__checkstyle(): PHPStan\Command\ErrorFormatter\CheckstyleErrorFormatter
	{
		return new PHPStan\Command\ErrorFormatter\CheckstyleErrorFormatter($this->getService('simpleRelativePathHelper'));
	}


	public function createServiceErrorFormatter__github(): PHPStan\Command\ErrorFormatter\GithubErrorFormatter
	{
		return new PHPStan\Command\ErrorFormatter\GithubErrorFormatter($this->getService('simpleRelativePathHelper'));
	}


	public function createServiceErrorFormatter__gitlab(): PHPStan\Command\ErrorFormatter\GitlabErrorFormatter
	{
		return new PHPStan\Command\ErrorFormatter\GitlabErrorFormatter($this->getService('simpleRelativePathHelper'));
	}


	public function createServiceErrorFormatter__json(): PHPStan\Command\ErrorFormatter\JsonErrorFormatter
	{
		return new PHPStan\Command\ErrorFormatter\JsonErrorFormatter(false);
	}


	public function createServiceErrorFormatter__junit(): PHPStan\Command\ErrorFormatter\JunitErrorFormatter
	{
		return new PHPStan\Command\ErrorFormatter\JunitErrorFormatter($this->getService('simpleRelativePathHelper'));
	}


	public function createServiceErrorFormatter__prettyJson(): PHPStan\Command\ErrorFormatter\JsonErrorFormatter
	{
		return new PHPStan\Command\ErrorFormatter\JsonErrorFormatter(true);
	}


	public function createServiceErrorFormatter__raw(): PHPStan\Command\ErrorFormatter\RawErrorFormatter
	{
		return new PHPStan\Command\ErrorFormatter\RawErrorFormatter;
	}


	public function createServiceErrorFormatter__table(): PHPStan\Command\ErrorFormatter\TableErrorFormatter
	{
		return new PHPStan\Command\ErrorFormatter\TableErrorFormatter(
			$this->getService('relativePathHelper'),
			$this->getService('simpleRelativePathHelper'),
			$this->getService('0369'),
			true,
			null,
			null
		);
	}


	public function createServiceErrorFormatter__teamcity(): PHPStan\Command\ErrorFormatter\TeamcityErrorFormatter
	{
		return new PHPStan\Command\ErrorFormatter\TeamcityErrorFormatter($this->getService('simpleRelativePathHelper'));
	}


	public function createServiceExceptionTypeResolver(): PHPStan\Rules\Exceptions\ExceptionTypeResolver
	{
		return $this->getService('0141');
	}


	public function createServiceFileExcluderAnalyse(): PHPStan\File\FileExcluder
	{
		return $this->getService('086')->createAnalyseFileExcluder();
	}


	public function createServiceFileExcluderScan(): PHPStan\File\FileExcluder
	{
		return $this->getService('086')->createScanFileExcluder();
	}


	public function createServiceFileFinderAnalyse(): PHPStan\File\FileFinder
	{
		return new PHPStan\File\FileFinder(
			$this->getService('fileExcluderAnalyse'),
			$this->getService('085'),
			['php', 'module', 'theme', 'inc', 'install', 'profile', 'engine']
		);
	}


	public function createServiceFileFinderScan(): PHPStan\File\FileFinder
	{
		return new PHPStan\File\FileFinder(
			$this->getService('fileExcluderScan'),
			$this->getService('085'),
			['php', 'module', 'theme', 'inc', 'install', 'profile', 'engine']
		);
	}


	public function createServiceFreshStubParser(): PHPStan\Parser\StubParser
	{
		return new PHPStan\Parser\StubParser($this->getService('php8PhpParser'), $this->getService('03'));
	}


	public function createServiceNodeScopeResolverReflector(): PHPStan\Reflection\BetterReflection\Reflector\MemoizingReflector
	{
		return $this->getService('betterReflectionReflector');
	}


	public function createServiceOriginalBetterReflectionReflector(): PHPStan\BetterReflection\Reflector\DefaultReflector
	{
		return new PHPStan\BetterReflection\Reflector\DefaultReflector($this->getService('betterReflectionSourceLocator'));
	}


	public function createServiceParentDirectoryRelativePathHelper(): PHPStan\File\ParentDirectoryRelativePathHelper
	{
		return new PHPStan\File\ParentDirectoryRelativePathHelper('/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal');
	}


	public function createServicePathRoutingParser(): PHPStan\Parser\PathRoutingParser
	{
		return new PHPStan\Parser\PathRoutingParser(
			$this->getService('085'),
			$this->getService('currentPhpVersionRichParser'),
			$this->getService('currentPhpVersionSimpleParser'),
			$this->getService('php8Parser'),
			$this->getParameter('singleReflectionFile')
		);
	}


	public function createServicePhp8Lexer(): PhpParser\Lexer\Emulative
	{
		return $this->getService('02')->createEmulative();
	}


	public function createServicePhp8Parser(): PHPStan\Parser\SimpleParser
	{
		return new PHPStan\Parser\SimpleParser(
			$this->getService('php8PhpParser'),
			$this->getService('03'),
			$this->getService('021'),
			$this->getService('022')
		);
	}


	public function createServicePhp8PhpParser(): PhpParser\Parser\Php8
	{
		return new PhpParser\Parser\Php8($this->getService('php8Lexer'));
	}


	public function createServicePhpParserDecorator(): PHPStan\Parser\PhpParserDecorator
	{
		return new PHPStan\Parser\PhpParserDecorator($this->getService('defaultAnalysisParser'));
	}


	public function createServicePhpstanDiagnoseExtension(): PHPStan\Diagnose\PHPStanDiagnoseExtension
	{
		return new PHPStan\Diagnose\PHPStanDiagnoseExtension(
			$this->getService('026'),
			null,
			$this->getService('085'),
			['/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal'],
			[
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/conf/parametersSchema.neon',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/conf/config.level0.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/composer/composer/phpstan/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/composer/pcre/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-deprecation-rules/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/phpstan-basic.neon',
			],
			$this->getService('029')
		);
	}


	public function createServiceReflectionProvider(): PHPStan\Reflection\ReflectionProvider
	{
		return $this->getService('reflectionProviderFactory')->create();
	}


	public function createServiceReflectionProviderFactory(): PHPStan\Reflection\ReflectionProvider\ReflectionProviderFactory
	{
		return new PHPStan\Reflection\ReflectionProvider\ReflectionProviderFactory($this->getService('betterReflectionProvider'));
	}


	public function createServiceRegistry(): PHPStan\Rules\LazyRegistry
	{
		return new PHPStan\Rules\LazyRegistry($this->getService('075'));
	}


	public function createServiceRelativePathHelper(): PHPStan\File\RelativePathHelper
	{
		return new PHPStan\File\FuzzyRelativePathHelper(
			$this->getService('parentDirectoryRelativePathHelper'),
			'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal',
			$this->getParameter('analysedPaths')
		);
	}


	public function createServiceRules__0(): PHPStan\Rules\Debug\DebugScopeRule
	{
		return new PHPStan\Rules\Debug\DebugScopeRule($this->getService('reflectionProvider'));
	}


	public function createServiceRules__1(): PHPStan\Rules\Debug\DumpPhpDocTypeRule
	{
		return new PHPStan\Rules\Debug\DumpPhpDocTypeRule($this->getService('reflectionProvider'), $this->getService('035'));
	}


	public function createServiceRules__10(): PHPStan\Rules\RestrictedUsage\RestrictedStaticMethodUsageRule
	{
		return new PHPStan\Rules\RestrictedUsage\RestrictedStaticMethodUsageRule(
			$this->getService('075'),
			$this->getService('reflectionProvider'),
			$this->getService('0182')
		);
	}


	public function createServiceRules__100(): PHPStan\Rules\Properties\PropertiesInInterfaceRule
	{
		return new PHPStan\Rules\Properties\PropertiesInInterfaceRule($this->getService('026'));
	}


	public function createServiceRules__101(): PHPStan\Rules\Properties\PropertyAssignRefRule
	{
		return new PHPStan\Rules\Properties\PropertyAssignRefRule($this->getService('026'), $this->getService('0180'));
	}


	public function createServiceRules__102(): PHPStan\Rules\Properties\PropertyAttributesRule
	{
		return new PHPStan\Rules\Properties\PropertyAttributesRule($this->getService('0130'));
	}


	public function createServiceRules__103(): PHPStan\Rules\Properties\PropertyHookAttributesRule
	{
		return new PHPStan\Rules\Properties\PropertyHookAttributesRule($this->getService('0130'));
	}


	public function createServiceRules__104(): PHPStan\Rules\Properties\PropertyInClassRule
	{
		return new PHPStan\Rules\Properties\PropertyInClassRule($this->getService('026'));
	}


	public function createServiceRules__105(): PHPStan\Rules\Properties\ReadOnlyPropertyRule
	{
		return new PHPStan\Rules\Properties\ReadOnlyPropertyRule($this->getService('026'));
	}


	public function createServiceRules__106(): PHPStan\Rules\Properties\ReadOnlyByPhpDocPropertyRule
	{
		return new PHPStan\Rules\Properties\ReadOnlyByPhpDocPropertyRule;
	}


	public function createServiceRules__107(): PHPStan\Rules\Regexp\RegularExpressionPatternRule
	{
		return new PHPStan\Rules\Regexp\RegularExpressionPatternRule($this->getService('0280'));
	}


	public function createServiceRules__108(): PHPStan\Rules\Traits\ConflictingTraitConstantsRule
	{
		return new PHPStan\Rules\Traits\ConflictingTraitConstantsRule($this->getService('096'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__109(): PHPStan\Rules\Traits\ConstantsInTraitsRule
	{
		return new PHPStan\Rules\Traits\ConstantsInTraitsRule($this->getService('026'));
	}


	public function createServiceRules__11(): PHPStan\Rules\RestrictedUsage\RestrictedStaticMethodCallableUsageRule
	{
		return new PHPStan\Rules\RestrictedUsage\RestrictedStaticMethodCallableUsageRule(
			$this->getService('075'),
			$this->getService('reflectionProvider'),
			$this->getService('0182')
		);
	}


	public function createServiceRules__110(): PHPStan\Rules\Traits\TraitAttributesRule
	{
		return new PHPStan\Rules\Traits\TraitAttributesRule($this->getService('0130'));
	}


	public function createServiceRules__111(): PHPStan\Rules\Types\InvalidTypesInUnionRule
	{
		return new PHPStan\Rules\Types\InvalidTypesInUnionRule;
	}


	public function createServiceRules__112(): PHPStan\Rules\Variables\UnsetRule
	{
		return new PHPStan\Rules\Variables\UnsetRule($this->getService('0180'), $this->getService('026'));
	}


	public function createServiceRules__113(): PHPStan\Rules\Whitespace\FileWhitespaceRule
	{
		return new PHPStan\Rules\Whitespace\FileWhitespaceRule;
	}


	public function createServiceRules__114(): Composer\Pcre\PHPStan\UnsafeStrictGroupsCallRule
	{
		return new Composer\Pcre\PHPStan\UnsafeStrictGroupsCallRule($this->getService('0278'));
	}


	public function createServiceRules__115(): Composer\Pcre\PHPStan\InvalidRegexPatternRule
	{
		return new Composer\Pcre\PHPStan\InvalidRegexPatternRule;
	}


	public function createServiceRules__116(): mglaman\PHPStanDrupal\Rules\Drupal\Coder\DiscouragedFunctionsRule
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\Coder\DiscouragedFunctionsRule;
	}


	public function createServiceRules__117(): mglaman\PHPStanDrupal\Rules\Drupal\GlobalDrupalDependencyInjectionRule
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\GlobalDrupalDependencyInjectionRule;
	}


	public function createServiceRules__118(): mglaman\PHPStanDrupal\Rules\Drupal\PluginManager\PluginManagerSetsCacheBackendRule
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\PluginManager\PluginManagerSetsCacheBackendRule;
	}


	public function createServiceRules__119(): mglaman\PHPStanDrupal\Rules\Drupal\RenderCallbackRule
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\RenderCallbackRule(
			$this->getService('reflectionProvider'),
			$this->getService('0404')
		);
	}


	public function createServiceRules__12(): PHPStan\Rules\RestrictedUsage\RestrictedStaticPropertyUsageRule
	{
		return new PHPStan\Rules\RestrictedUsage\RestrictedStaticPropertyUsageRule(
			$this->getService('075'),
			$this->getService('reflectionProvider'),
			$this->getService('0182')
		);
	}


	public function createServiceRules__120(): mglaman\PHPStanDrupal\Rules\Deprecations\StaticServiceDeprecatedServiceRule
	{
		return new mglaman\PHPStanDrupal\Rules\Deprecations\StaticServiceDeprecatedServiceRule($this->getService('0404'));
	}


	public function createServiceRules__121(): mglaman\PHPStanDrupal\Rules\Deprecations\GetDeprecatedServiceRule
	{
		return new mglaman\PHPStanDrupal\Rules\Deprecations\GetDeprecatedServiceRule($this->getService('0404'));
	}


	public function createServiceRules__122(): mglaman\PHPStanDrupal\Rules\Drupal\Tests\BrowserTestBaseDefaultThemeRule
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\Tests\BrowserTestBaseDefaultThemeRule;
	}


	public function createServiceRules__123(): mglaman\PHPStanDrupal\Rules\Deprecations\ConfigEntityConfigExportRule
	{
		return new mglaman\PHPStanDrupal\Rules\Deprecations\ConfigEntityConfigExportRule($this->getService('reflectionProvider'));
	}


	public function createServiceRules__124(): mglaman\PHPStanDrupal\Rules\Deprecations\PluginAnnotationContextDefinitionsRule
	{
		return new mglaman\PHPStanDrupal\Rules\Deprecations\PluginAnnotationContextDefinitionsRule($this->getService('reflectionProvider'));
	}


	public function createServiceRules__125(): mglaman\PHPStanDrupal\Rules\Drupal\ModuleLoadInclude
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\ModuleLoadInclude($this->getService('0405'));
	}


	public function createServiceRules__126(): mglaman\PHPStanDrupal\Rules\Drupal\LoadIncludes
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\LoadIncludes($this->getService('0405'));
	}


	public function createServiceRules__127(): mglaman\PHPStanDrupal\Rules\Drupal\EntityQuery\EntityQueryHasAccessCheckRule
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\EntityQuery\EntityQueryHasAccessCheckRule;
	}


	public function createServiceRules__128(): mglaman\PHPStanDrupal\Rules\Drupal\TestClassesProtectedPropertyModulesRule
	{
		return new mglaman\PHPStanDrupal\Rules\Drupal\TestClassesProtectedPropertyModulesRule;
	}


	public function createServiceRules__129(): PHPStan\Rules\Deprecations\FetchingDeprecatedConstRule
	{
		return new PHPStan\Rules\Deprecations\FetchingDeprecatedConstRule(
			$this->getService('reflectionProvider'),
			$this->getService('0433')
		);
	}


	public function createServiceRules__13(): PHPStan\Rules\RestrictedUsage\RestrictedUsageOfDeprecatedStringCastRule
	{
		return new PHPStan\Rules\RestrictedUsage\RestrictedUsageOfDeprecatedStringCastRule(
			$this->getService('075'),
			$this->getService('reflectionProvider')
		);
	}


	public function createServiceRules__130(): PHPStan\Rules\PHPUnit\AssertSameBooleanExpectedRule
	{
		return new PHPStan\Rules\PHPUnit\AssertSameBooleanExpectedRule;
	}


	public function createServiceRules__131(): PHPStan\Rules\PHPUnit\AssertSameNullExpectedRule
	{
		return new PHPStan\Rules\PHPUnit\AssertSameNullExpectedRule;
	}


	public function createServiceRules__132(): PHPStan\Rules\PHPUnit\AssertSameWithCountRule
	{
		return new PHPStan\Rules\PHPUnit\AssertSameWithCountRule;
	}


	public function createServiceRules__133(): PHPStan\Rules\PHPUnit\ClassCoversExistsRule
	{
		return new PHPStan\Rules\PHPUnit\ClassCoversExistsRule($this->getService('0446'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__134(): PHPStan\Rules\PHPUnit\ClassMethodCoversExistsRule
	{
		return new PHPStan\Rules\PHPUnit\ClassMethodCoversExistsRule($this->getService('0446'), $this->getService('0185'));
	}


	public function createServiceRules__135(): PHPStan\Rules\PHPUnit\MockMethodCallRule
	{
		return new PHPStan\Rules\PHPUnit\MockMethodCallRule;
	}


	public function createServiceRules__136(): PHPStan\Rules\PHPUnit\NoMissingSpaceInClassAnnotationRule
	{
		return new PHPStan\Rules\PHPUnit\NoMissingSpaceInClassAnnotationRule($this->getService('0447'));
	}


	public function createServiceRules__137(): PHPStan\Rules\PHPUnit\NoMissingSpaceInMethodAnnotationRule
	{
		return new PHPStan\Rules\PHPUnit\NoMissingSpaceInMethodAnnotationRule($this->getService('0447'));
	}


	public function createServiceRules__138(): PHPStan\Rules\PHPUnit\ShouldCallParentMethodsRule
	{
		return new PHPStan\Rules\PHPUnit\ShouldCallParentMethodsRule;
	}


	public function createServiceRules__14(): PHPStan\Rules\Api\ApiInstanceofRule
	{
		return new PHPStan\Rules\Api\ApiInstanceofRule($this->getService('0129'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__15(): PHPStan\Rules\Api\ApiInstanceofTypeRule
	{
		return new PHPStan\Rules\Api\ApiInstanceofTypeRule($this->getService('reflectionProvider'));
	}


	public function createServiceRules__16(): PHPStan\Rules\Api\ApiInstantiationRule
	{
		return new PHPStan\Rules\Api\ApiInstantiationRule($this->getService('0129'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__17(): PHPStan\Rules\Api\ApiClassConstFetchRule
	{
		return new PHPStan\Rules\Api\ApiClassConstFetchRule($this->getService('0129'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__18(): PHPStan\Rules\Api\ApiClassExtendsRule
	{
		return new PHPStan\Rules\Api\ApiClassExtendsRule($this->getService('0129'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__19(): PHPStan\Rules\Api\ApiClassImplementsRule
	{
		return new PHPStan\Rules\Api\ApiClassImplementsRule($this->getService('0129'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__2(): PHPStan\Rules\Debug\DumpTypeRule
	{
		return new PHPStan\Rules\Debug\DumpTypeRule($this->getService('reflectionProvider'));
	}


	public function createServiceRules__20(): PHPStan\Rules\Api\ApiInterfaceExtendsRule
	{
		return new PHPStan\Rules\Api\ApiInterfaceExtendsRule($this->getService('0129'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__21(): PHPStan\Rules\Api\ApiMethodCallRule
	{
		return new PHPStan\Rules\Api\ApiMethodCallRule($this->getService('0129'));
	}


	public function createServiceRules__22(): PHPStan\Rules\Api\ApiStaticCallRule
	{
		return new PHPStan\Rules\Api\ApiStaticCallRule($this->getService('0129'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__23(): PHPStan\Rules\Api\ApiTraitUseRule
	{
		return new PHPStan\Rules\Api\ApiTraitUseRule($this->getService('0129'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__24(): PHPStan\Rules\Api\GetTemplateTypeRule
	{
		return new PHPStan\Rules\Api\GetTemplateTypeRule($this->getService('reflectionProvider'));
	}


	public function createServiceRules__25(): PHPStan\Rules\Api\NodeConnectingVisitorAttributesRule
	{
		return new PHPStan\Rules\Api\NodeConnectingVisitorAttributesRule;
	}


	public function createServiceRules__26(): PHPStan\Rules\Api\OldPhpParser4ClassRule
	{
		return new PHPStan\Rules\Api\OldPhpParser4ClassRule;
	}


	public function createServiceRules__27(): PHPStan\Rules\Api\PhpStanNamespaceIn3rdPartyPackageRule
	{
		return new PHPStan\Rules\Api\PhpStanNamespaceIn3rdPartyPackageRule($this->getService('0129'));
	}


	public function createServiceRules__28(): PHPStan\Rules\Api\RuntimeReflectionInstantiationRule
	{
		return new PHPStan\Rules\Api\RuntimeReflectionInstantiationRule($this->getService('reflectionProvider'));
	}


	public function createServiceRules__29(): PHPStan\Rules\Api\RuntimeReflectionFunctionRule
	{
		return new PHPStan\Rules\Api\RuntimeReflectionFunctionRule($this->getService('reflectionProvider'));
	}


	public function createServiceRules__3(): PHPStan\Rules\Debug\FileAssertRule
	{
		return new PHPStan\Rules\Debug\FileAssertRule($this->getService('reflectionProvider'));
	}


	public function createServiceRules__30(): PHPStan\Rules\Arrays\DuplicateKeysInLiteralArraysRule
	{
		return new PHPStan\Rules\Arrays\DuplicateKeysInLiteralArraysRule($this->getService('023'));
	}


	public function createServiceRules__31(): PHPStan\Rules\Arrays\OffsetAccessWithoutDimForReadingRule
	{
		return new PHPStan\Rules\Arrays\OffsetAccessWithoutDimForReadingRule;
	}


	public function createServiceRules__32(): PHPStan\Rules\Cast\UnsetCastRule
	{
		return new PHPStan\Rules\Cast\UnsetCastRule($this->getService('026'));
	}


	public function createServiceRules__33(): PHPStan\Rules\Classes\AllowedSubTypesRule
	{
		return new PHPStan\Rules\Classes\AllowedSubTypesRule;
	}


	public function createServiceRules__34(): PHPStan\Rules\Classes\ClassAttributesRule
	{
		return new PHPStan\Rules\Classes\ClassAttributesRule($this->getService('0130'));
	}


	public function createServiceRules__35(): PHPStan\Rules\Classes\ClassConstantAttributesRule
	{
		return new PHPStan\Rules\Classes\ClassConstantAttributesRule($this->getService('0130'));
	}


	public function createServiceRules__36(): PHPStan\Rules\Classes\ClassConstantRule
	{
		return new PHPStan\Rules\Classes\ClassConstantRule(
			$this->getService('reflectionProvider'),
			$this->getService('0182'),
			$this->getService('0132'),
			$this->getService('026')
		);
	}


	public function createServiceRules__37(): PHPStan\Rules\Classes\DuplicateDeclarationRule
	{
		return new PHPStan\Rules\Classes\DuplicateDeclarationRule;
	}


	public function createServiceRules__38(): PHPStan\Rules\Classes\EnumSanityRule
	{
		return new PHPStan\Rules\Classes\EnumSanityRule;
	}


	public function createServiceRules__39(): PHPStan\Rules\Classes\InstantiationCallableRule
	{
		return new PHPStan\Rules\Classes\InstantiationCallableRule;
	}


	public function createServiceRules__4(): PHPStan\Rules\RestrictedUsage\RestrictedClassConstantUsageRule
	{
		return new PHPStan\Rules\RestrictedUsage\RestrictedClassConstantUsageRule(
			$this->getService('075'),
			$this->getService('reflectionProvider'),
			$this->getService('0182')
		);
	}


	public function createServiceRules__40(): PHPStan\Rules\Classes\InvalidPromotedPropertiesRule
	{
		return new PHPStan\Rules\Classes\InvalidPromotedPropertiesRule($this->getService('026'));
	}


	public function createServiceRules__41(): PHPStan\Rules\Classes\LocalTypeAliasesRule
	{
		return new PHPStan\Rules\Classes\LocalTypeAliasesRule($this->getService('0135'));
	}


	public function createServiceRules__42(): PHPStan\Rules\Classes\LocalTypeTraitUseAliasesRule
	{
		return new PHPStan\Rules\Classes\LocalTypeTraitUseAliasesRule($this->getService('0135'));
	}


	public function createServiceRules__43(): PHPStan\Rules\Classes\LocalTypeTraitAliasesRule
	{
		return new PHPStan\Rules\Classes\LocalTypeTraitAliasesRule($this->getService('0135'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__44(): PHPStan\Rules\Classes\NewStaticRule
	{
		return new PHPStan\Rules\Classes\NewStaticRule;
	}


	public function createServiceRules__45(): PHPStan\Rules\Classes\NonClassAttributeClassRule
	{
		return new PHPStan\Rules\Classes\NonClassAttributeClassRule;
	}


	public function createServiceRules__46(): PHPStan\Rules\Classes\ReadOnlyClassRule
	{
		return new PHPStan\Rules\Classes\ReadOnlyClassRule($this->getService('026'));
	}


	public function createServiceRules__47(): PHPStan\Rules\Classes\TraitAttributeClassRule
	{
		return new PHPStan\Rules\Classes\TraitAttributeClassRule;
	}


	public function createServiceRules__48(): PHPStan\Rules\Constants\ClassAsClassConstantRule
	{
		return new PHPStan\Rules\Constants\ClassAsClassConstantRule;
	}


	public function createServiceRules__49(): PHPStan\Rules\Constants\DynamicClassConstantFetchRule
	{
		return new PHPStan\Rules\Constants\DynamicClassConstantFetchRule($this->getService('026'), $this->getService('0182'));
	}


	public function createServiceRules__5(): PHPStan\Rules\RestrictedUsage\RestrictedFunctionUsageRule
	{
		return new PHPStan\Rules\RestrictedUsage\RestrictedFunctionUsageRule(
			$this->getService('075'),
			$this->getService('reflectionProvider')
		);
	}


	public function createServiceRules__50(): PHPStan\Rules\Constants\FinalConstantRule
	{
		return new PHPStan\Rules\Constants\FinalConstantRule($this->getService('026'));
	}


	public function createServiceRules__51(): PHPStan\Rules\Constants\MagicConstantContextRule
	{
		return new PHPStan\Rules\Constants\MagicConstantContextRule;
	}


	public function createServiceRules__52(): PHPStan\Rules\Constants\NativeTypedClassConstantRule
	{
		return new PHPStan\Rules\Constants\NativeTypedClassConstantRule($this->getService('026'));
	}


	public function createServiceRules__53(): PHPStan\Rules\Constants\FinalPrivateConstantRule
	{
		return new PHPStan\Rules\Constants\FinalPrivateConstantRule;
	}


	public function createServiceRules__54(): PHPStan\Rules\EnumCases\EnumCaseAttributesRule
	{
		return new PHPStan\Rules\EnumCases\EnumCaseAttributesRule($this->getService('0130'));
	}


	public function createServiceRules__55(): PHPStan\Rules\Exceptions\NoncapturingCatchRule
	{
		return new PHPStan\Rules\Exceptions\NoncapturingCatchRule;
	}


	public function createServiceRules__56(): PHPStan\Rules\Exceptions\ThrowExpressionRule
	{
		return new PHPStan\Rules\Exceptions\ThrowExpressionRule($this->getService('026'));
	}


	public function createServiceRules__57(): PHPStan\Rules\Functions\ArrowFunctionAttributesRule
	{
		return new PHPStan\Rules\Functions\ArrowFunctionAttributesRule($this->getService('0130'));
	}


	public function createServiceRules__58(): PHPStan\Rules\Functions\ArrowFunctionReturnNullsafeByRefRule
	{
		return new PHPStan\Rules\Functions\ArrowFunctionReturnNullsafeByRefRule($this->getService('0165'));
	}


	public function createServiceRules__59(): PHPStan\Rules\Functions\ClosureAttributesRule
	{
		return new PHPStan\Rules\Functions\ClosureAttributesRule($this->getService('0130'));
	}


	public function createServiceRules__6(): PHPStan\Rules\RestrictedUsage\RestrictedFunctionCallableUsageRule
	{
		return new PHPStan\Rules\RestrictedUsage\RestrictedFunctionCallableUsageRule(
			$this->getService('075'),
			$this->getService('reflectionProvider')
		);
	}


	public function createServiceRules__60(): PHPStan\Rules\Functions\DefineParametersRule
	{
		return new PHPStan\Rules\Functions\DefineParametersRule($this->getService('026'));
	}


	public function createServiceRules__61(): PHPStan\Rules\Functions\ExistingClassesInArrowFunctionTypehintsRule
	{
		return new PHPStan\Rules\Functions\ExistingClassesInArrowFunctionTypehintsRule(
			$this->getService('0148'),
			$this->getService('026')
		);
	}


	public function createServiceRules__62(): PHPStan\Rules\Functions\CallToFunctionParametersRule
	{
		return new PHPStan\Rules\Functions\CallToFunctionParametersRule(
			$this->getService('reflectionProvider'),
			$this->getService('0147')
		);
	}


	public function createServiceRules__63(): PHPStan\Rules\Functions\ExistingClassesInClosureTypehintsRule
	{
		return new PHPStan\Rules\Functions\ExistingClassesInClosureTypehintsRule($this->getService('0148'));
	}


	public function createServiceRules__64(): PHPStan\Rules\Functions\ExistingClassesInTypehintsRule
	{
		return new PHPStan\Rules\Functions\ExistingClassesInTypehintsRule($this->getService('0148'));
	}


	public function createServiceRules__65(): PHPStan\Rules\Functions\FunctionAttributesRule
	{
		return new PHPStan\Rules\Functions\FunctionAttributesRule($this->getService('0130'));
	}


	public function createServiceRules__66(): PHPStan\Rules\Functions\InnerFunctionRule
	{
		return new PHPStan\Rules\Functions\InnerFunctionRule;
	}


	public function createServiceRules__67(): PHPStan\Rules\Functions\InvalidLexicalVariablesInClosureUseRule
	{
		return new PHPStan\Rules\Functions\InvalidLexicalVariablesInClosureUseRule;
	}


	public function createServiceRules__68(): PHPStan\Rules\Functions\ParamAttributesRule
	{
		return new PHPStan\Rules\Functions\ParamAttributesRule($this->getService('0130'));
	}


	public function createServiceRules__69(): PHPStan\Rules\Functions\PrintfArrayParametersRule
	{
		return new PHPStan\Rules\Functions\PrintfArrayParametersRule($this->getService('0361'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__7(): PHPStan\Rules\RestrictedUsage\RestrictedMethodUsageRule
	{
		return new PHPStan\Rules\RestrictedUsage\RestrictedMethodUsageRule(
			$this->getService('075'),
			$this->getService('reflectionProvider')
		);
	}


	public function createServiceRules__70(): PHPStan\Rules\Functions\PrintfParametersRule
	{
		return new PHPStan\Rules\Functions\PrintfParametersRule($this->getService('0361'), $this->getService('reflectionProvider'));
	}


	public function createServiceRules__71(): PHPStan\Rules\Functions\RedefinedParametersRule
	{
		return new PHPStan\Rules\Functions\RedefinedParametersRule;
	}


	public function createServiceRules__72(): PHPStan\Rules\Functions\ReturnNullsafeByRefRule
	{
		return new PHPStan\Rules\Functions\ReturnNullsafeByRefRule($this->getService('0165'));
	}


	public function createServiceRules__73(): PHPStan\Rules\Ignore\IgnoreParseErrorRule
	{
		return new PHPStan\Rules\Ignore\IgnoreParseErrorRule;
	}


	public function createServiceRules__74(): PHPStan\Rules\Functions\VariadicParametersDeclarationRule
	{
		return new PHPStan\Rules\Functions\VariadicParametersDeclarationRule;
	}


	public function createServiceRules__75(): PHPStan\Rules\Keywords\ContinueBreakInLoopRule
	{
		return new PHPStan\Rules\Keywords\ContinueBreakInLoopRule;
	}


	public function createServiceRules__76(): PHPStan\Rules\Keywords\DeclareStrictTypesRule
	{
		return new PHPStan\Rules\Keywords\DeclareStrictTypesRule($this->getService('023'));
	}


	public function createServiceRules__77(): PHPStan\Rules\Methods\AbstractMethodInNonAbstractClassRule
	{
		return new PHPStan\Rules\Methods\AbstractMethodInNonAbstractClassRule;
	}


	public function createServiceRules__78(): PHPStan\Rules\Methods\AbstractPrivateMethodRule
	{
		return new PHPStan\Rules\Methods\AbstractPrivateMethodRule;
	}


	public function createServiceRules__79(): PHPStan\Rules\Methods\CallMethodsRule
	{
		return new PHPStan\Rules\Methods\CallMethodsRule($this->getService('0159'), $this->getService('0147'));
	}


	public function createServiceRules__8(): PHPStan\Rules\RestrictedUsage\RestrictedMethodCallableUsageRule
	{
		return new PHPStan\Rules\RestrictedUsage\RestrictedMethodCallableUsageRule(
			$this->getService('075'),
			$this->getService('reflectionProvider')
		);
	}


	public function createServiceRules__80(): PHPStan\Rules\Methods\CallStaticMethodsRule
	{
		return new PHPStan\Rules\Methods\CallStaticMethodsRule($this->getService('0160'), $this->getService('0147'));
	}


	public function createServiceRules__81(): PHPStan\Rules\Methods\ConsistentConstructorRule
	{
		return new PHPStan\Rules\Methods\ConsistentConstructorRule($this->getService('0162'), $this->getService('0163'));
	}


	public function createServiceRules__82(): PHPStan\Rules\Methods\ConstructorReturnTypeRule
	{
		return new PHPStan\Rules\Methods\ConstructorReturnTypeRule;
	}


	public function createServiceRules__83(): PHPStan\Rules\Methods\ExistingClassesInTypehintsRule
	{
		return new PHPStan\Rules\Methods\ExistingClassesInTypehintsRule($this->getService('0148'));
	}


	public function createServiceRules__84(): PHPStan\Rules\Methods\FinalPrivateMethodRule
	{
		return new PHPStan\Rules\Methods\FinalPrivateMethodRule;
	}


	public function createServiceRules__85(): PHPStan\Rules\Methods\MethodCallableRule
	{
		return new PHPStan\Rules\Methods\MethodCallableRule($this->getService('0159'), $this->getService('026'));
	}


	public function createServiceRules__86(): PHPStan\Rules\Methods\MethodVisibilityInInterfaceRule
	{
		return new PHPStan\Rules\Methods\MethodVisibilityInInterfaceRule;
	}


	public function createServiceRules__87(): PHPStan\Rules\Methods\MissingMagicSerializationMethodsRule
	{
		return new PHPStan\Rules\Methods\MissingMagicSerializationMethodsRule($this->getService('026'));
	}


	public function createServiceRules__88(): PHPStan\Rules\Methods\MissingMethodImplementationRule
	{
		return new PHPStan\Rules\Methods\MissingMethodImplementationRule;
	}


	public function createServiceRules__89(): PHPStan\Rules\Methods\MethodAttributesRule
	{
		return new PHPStan\Rules\Methods\MethodAttributesRule($this->getService('0130'));
	}


	public function createServiceRules__9(): PHPStan\Rules\RestrictedUsage\RestrictedPropertyUsageRule
	{
		return new PHPStan\Rules\RestrictedUsage\RestrictedPropertyUsageRule(
			$this->getService('075'),
			$this->getService('reflectionProvider')
		);
	}


	public function createServiceRules__90(): PHPStan\Rules\Methods\StaticMethodCallableRule
	{
		return new PHPStan\Rules\Methods\StaticMethodCallableRule($this->getService('0160'), $this->getService('026'));
	}


	public function createServiceRules__91(): PHPStan\Rules\Names\UsedNamesRule
	{
		return new PHPStan\Rules\Names\UsedNamesRule;
	}


	public function createServiceRules__92(): PHPStan\Rules\Operators\InvalidAssignVarRule
	{
		return new PHPStan\Rules\Operators\InvalidAssignVarRule($this->getService('0165'));
	}


	public function createServiceRules__93(): PHPStan\Rules\Operators\InvalidIncDecOperationRule
	{
		return new PHPStan\Rules\Operators\InvalidIncDecOperationRule($this->getService('0182'));
	}


	public function createServiceRules__94(): PHPStan\Rules\Properties\AccessPropertiesInAssignRule
	{
		return new PHPStan\Rules\Properties\AccessPropertiesInAssignRule($this->getService('0175'));
	}


	public function createServiceRules__95(): PHPStan\Rules\Properties\AccessStaticPropertiesInAssignRule
	{
		return new PHPStan\Rules\Properties\AccessStaticPropertiesInAssignRule($this->getService('0386'));
	}


	public function createServiceRules__96(): PHPStan\Rules\Properties\ExistingClassesInPropertyHookTypehintsRule
	{
		return new PHPStan\Rules\Properties\ExistingClassesInPropertyHookTypehintsRule($this->getService('0148'));
	}


	public function createServiceRules__97(): PHPStan\Rules\Properties\InvalidCallablePropertyTypeRule
	{
		return new PHPStan\Rules\Properties\InvalidCallablePropertyTypeRule;
	}


	public function createServiceRules__98(): PHPStan\Rules\Properties\MissingReadOnlyPropertyAssignRule
	{
		return new PHPStan\Rules\Properties\MissingReadOnlyPropertyAssignRule($this->getService('0110'));
	}


	public function createServiceRules__99(): PHPStan\Rules\Properties\MissingReadOnlyByPhpDocPropertyAssignRule
	{
		return new PHPStan\Rules\Properties\MissingReadOnlyByPhpDocPropertyAssignRule($this->getService('0110'));
	}


	public function createServiceSimpleRelativePathHelper(): PHPStan\File\RelativePathHelper
	{
		return new PHPStan\File\SimpleRelativePathHelper('/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal');
	}


	public function createServiceStubFileTypeMapper(): PHPStan\Type\FileTypeMapper
	{
		return new PHPStan\Type\FileTypeMapper(
			$this->getService('0122'),
			$this->getService('stubParser'),
			$this->getService('038'),
			$this->getService('037'),
			$this->getService('025'),
			$this->getService('085')
		);
	}


	public function createServiceStubParser(): PHPStan\Parser\CachedParser
	{
		return new PHPStan\Parser\CachedParser($this->getService('freshStubParser'), 256);
	}


	public function createServiceStubPhpDocProvider(): PHPStan\PhpDoc\StubPhpDocProvider
	{
		return new PHPStan\PhpDoc\StubPhpDocProvider(
			$this->getService('stubParser'),
			$this->getService('stubFileTypeMapper'),
			$this->getService('045')
		);
	}


	public function createServiceTypeSpecifier(): PHPStan\Analyser\TypeSpecifier
	{
		return $this->getService('typeSpecifierFactory')->create();
	}


	public function createServiceTypeSpecifierFactory(): PHPStan\Analyser\TypeSpecifierFactory
	{
		return new PHPStan\Analyser\TypeSpecifierFactory($this->getService('075'));
	}


	public function initialize(): void
	{
	}


	protected function getStaticParameters(): array
	{
		return [
			'bootstrapFiles' => [
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/ReflectionUnionType.php',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/ReflectionAttribute.php',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/Attribute.php',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/runtime/ReflectionIntersectionType.php',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/drupal-autoloader.php',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/web/core/tests/bootstrap.php',
			],
			'excludePaths' => ['analyseAndScan' => ['*.api.php', '*/tests/fixtures/*.php'], 'analyse' => []],
			'level' => 0,
			'paths' => ['/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/src'],
			'exceptions' => [
				'implicitThrows' => true,
				'reportUncheckedExceptionDeadCatch' => true,
				'uncheckedExceptionRegexes' => ['#^PHPUnit\\\#', '#^SebastianBergmann\\\#'],
				'uncheckedExceptionClasses' => [],
				'checkedExceptionRegexes' => [],
				'checkedExceptionClasses' => [],
				'check' => ['missingCheckedExceptionInThrows' => false, 'tooWideThrowType' => true],
			],
			'featureToggles' => [
				'bleedingEdge' => false,
				'checkParameterCastableToNumberFunctions' => false,
				'skipCheckGenericClasses' => [],
				'stricterFunctionMap' => false,
				'reportPreciseLineForUnusedFunctionParameter' => false,
				'internalTag' => false,
				'newStaticInAbstractClassStaticMethod' => false,
			],
			'fileExtensions' => ['php', 'module', 'theme', 'inc', 'install', 'profile', 'engine'],
			'checkAdvancedIsset' => false,
			'reportAlwaysTrueInLastCondition' => false,
			'checkClassCaseSensitivity' => false,
			'checkExplicitMixed' => false,
			'checkImplicitMixed' => false,
			'checkFunctionArgumentTypes' => false,
			'checkFunctionNameCase' => false,
			'checkInternalClassCaseSensitivity' => false,
			'checkMissingCallableSignature' => false,
			'checkMissingVarTagTypehint' => false,
			'checkArgumentsPassedByReference' => false,
			'checkMaybeUndefinedVariables' => false,
			'checkNullables' => false,
			'checkThisOnly' => true,
			'checkUnionTypes' => false,
			'checkBenevolentUnionTypes' => false,
			'checkExplicitMixedMissingReturn' => false,
			'checkPhpDocMissingReturn' => false,
			'checkPhpDocMethodSignatures' => false,
			'checkExtraArguments' => false,
			'checkMissingTypehints' => false,
			'checkTooWideReturnTypesInProtectedAndPublicMethods' => false,
			'checkUninitializedProperties' => false,
			'checkDynamicProperties' => false,
			'strictRulesInstalled' => false,
			'deprecationRulesInstalled' => true,
			'inferPrivatePropertyTypeFromConstructor' => false,
			'reportMaybes' => false,
			'reportMaybesInMethodSignatures' => false,
			'reportMaybesInPropertyPhpDocTypes' => false,
			'reportStaticMethodSignatures' => false,
			'reportWrongPhpDocTypeInVarTag' => false,
			'reportAnyTypeWideningInVarTag' => false,
			'reportPossiblyNonexistentGeneralArrayOffset' => false,
			'reportPossiblyNonexistentConstantArrayOffset' => false,
			'checkMissingOverrideMethodAttribute' => false,
			'mixinExcludeClasses' => [],
			'scanFiles' => [
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/stubs/Twig/functions.stub',
			],
			'scanDirectories' => [],
			'parallel' => [
				'jobSize' => 20,
				'processTimeout' => 600.0,
				'maximumNumberOfProcesses' => 32,
				'minimumNumberOfJobsPerProcess' => 2,
				'buffer' => 134217728,
			],
			'phpVersion' => null,
			'polluteScopeWithLoopInitialAssignments' => true,
			'polluteScopeWithAlwaysIterableForeach' => true,
			'polluteScopeWithBlock' => true,
			'propertyAlwaysWrittenTags' => [],
			'propertyAlwaysReadTags' => [],
			'additionalConstructors' => ['PHPUnit\Framework\TestCase::setUp'],
			'treatPhpDocTypesAsCertain' => true,
			'usePathConstantsAsConstantString' => false,
			'rememberPossiblyImpureFunctionValues' => true,
			'tips' => ['discoveringSymbols' => true, 'treatPhpDocTypesAsCertain' => true],
			'tipsOfTheDay' => true,
			'reportMagicMethods' => false,
			'reportMagicProperties' => false,
			'ignoreErrors' => ['#Cannot call method [a-zA-Z]+\(\) on mixed#', '#Property .* does not accept array#'],
			'internalErrorsCountLimit' => 50,
			'cache' => ['nodesByStringCountMax' => 256],
			'reportUnmatchedIgnoredErrors' => true,
			'typeAliases' => [],
			'universalObjectCratesClasses' => ['stdClass'],
			'stubFiles' => [
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionAttribute.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionClassConstant.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionFunctionAbstract.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionMethod.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionParameter.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ReflectionProperty.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/iterable.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ArrayObject.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/WeakReference.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ext-ds.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ImagickPixel.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/PDOStatement.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/date.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/ibm_db2.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/mysqli.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/zip.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/dom.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/spl.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/SplObjectStorage.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/Exception.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/arrayFunctions.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/core.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/typeCheckingFunctions.stub',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/stubs/Countable.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/Assert.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/AssertionFailedError.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/ExpectationFailedException.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/MockBuilder.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/MockObject.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/Stub.stub',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/stubs/TestCase.stub',
			],
			'earlyTerminatingMethodCalls' => ['PHPUnit\Framework\Assert' => ['fail', 'markTestIncomplete', 'markTestSkipped']],
			'earlyTerminatingFunctionCalls' => [],
			'resultCachePath' => '/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/var/phpstan/resultCache.php',
			'resultCacheSkipIfOlderThanDays' => 7,
			'resultCacheChecksProjectExtensionFilesDependencies' => false,
			'dynamicConstantNames' => [
				'ICONV_IMPL',
				'LIBXML_VERSION',
				'LIBXML_DOTTED_VERSION',
				'Memcached::HAVE_ENCODING',
				'Memcached::HAVE_IGBINARY',
				'Memcached::HAVE_JSON',
				'Memcached::HAVE_MSGPACK',
				'Memcached::HAVE_SASL',
				'Memcached::HAVE_SESSION',
				'PHP_VERSION',
				'PHP_MAJOR_VERSION',
				'PHP_MINOR_VERSION',
				'PHP_RELEASE_VERSION',
				'PHP_VERSION_ID',
				'PHP_EXTRA_VERSION',
				'PHP_WINDOWS_VERSION_MAJOR',
				'PHP_WINDOWS_VERSION_MINOR',
				'PHP_WINDOWS_VERSION_BUILD',
				'PHP_ZTS',
				'PHP_DEBUG',
				'PHP_MAXPATHLEN',
				'PHP_OS',
				'PHP_OS_FAMILY',
				'PHP_SAPI',
				'PHP_EOL',
				'PHP_INT_MAX',
				'PHP_INT_MIN',
				'PHP_INT_SIZE',
				'PHP_FLOAT_DIG',
				'PHP_FLOAT_EPSILON',
				'PHP_FLOAT_MIN',
				'PHP_FLOAT_MAX',
				'DEFAULT_INCLUDE_PATH',
				'PEAR_INSTALL_DIR',
				'PEAR_EXTENSION_DIR',
				'PHP_EXTENSION_DIR',
				'PHP_PREFIX',
				'PHP_BINDIR',
				'PHP_BINARY',
				'PHP_MANDIR',
				'PHP_LIBDIR',
				'PHP_DATADIR',
				'PHP_SYSCONFDIR',
				'PHP_LOCALSTATEDIR',
				'PHP_CONFIG_FILE_PATH',
				'PHP_CONFIG_FILE_SCAN_DIR',
				'PHP_SHLIB_SUFFIX',
				'PHP_FD_SETSIZE',
				'OPENSSL_VERSION_NUMBER',
				'ZEND_DEBUG_BUILD',
				'ZEND_THREAD_SAFE',
				'E_ALL',
				'Drupal::VERSION',
			],
			'customRulesetUsed' => false,
			'editorUrl' => null,
			'editorUrlTitle' => null,
			'errorFormat' => null,
			'sourceLocatorPlaygroundMode' => false,
			'__validate' => true,
			'parametersNotInvalidatingCache' => [
				['parameters', 'editorUrl'],
				['parameters', 'editorUrlTitle'],
				['parameters', 'errorFormat'],
				['parameters', 'ignoreErrors'],
				['parameters', 'reportUnmatchedIgnoredErrors'],
				['parameters', 'tipsOfTheDay'],
				['parameters', 'parallel'],
				['parameters', 'internalErrorsCountLimit'],
				['parameters', 'cache'],
				['parameters', 'memoryLimitFile'],
				['parameters', 'pro'],
				'parametersSchema',
			],
			'drupal' => [
				'drupal_root' => null,
				'bleedingEdge' => [
					'checkDeprecatedHooksInApiFiles' => false,
					'checkCoreDeprecatedHooksInApiFiles' => false,
					'checkContribDeprecatedHooksInApiFiles' => false,
				],
				'extensions' => [
					'entityFieldsViaMagicReflection' => true,
					'entityFieldMethodsViaMagicReflection' => true,
					'entityQuery' => true,
					'entityRepository' => true,
					'stubFiles' => true,
				],
				'rules' => [
					'testClassSuffixNameRule' => false,
					'dependencySerializationTraitPropertyRule' => false,
					'accessResultConditionRule' => false,
					'classExtendsInternalClassRule' => true,
					'pluginManagerInspectionRule' => false,
				],
				'entityMapping' => [
					'aggregator_feed' => [
						'class' => 'Drupal\aggregator\Entity\Feed',
						'storage' => 'Drupal\aggregator\FeedStorage',
					],
					'aggregator_item' => [
						'class' => 'Drupal\aggregator\Entity\Item',
						'storage' => 'Drupal\aggregator\ItemStorage',
					],
					'block' => [
						'class' => 'Drupal\block\Entity\Block',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'block_content' => [
						'class' => 'Drupal\block_content\Entity\BlockContent',
						'storage' => 'Drupal\Core\Entity\Sql\SqlContentEntityStorage',
					],
					'block_content_type' => [
						'class' => 'Drupal\block_content\Entity\BlockContentType',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'comment_type' => [
						'class' => 'Drupal\comment\Entity\CommentType',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'comment' => ['class' => 'Drupal\comment\Entity\Comment', 'storage' => 'Drupal\comment\CommentStorage'],
					'contact_form' => [
						'class' => 'Drupal\contact\Entity\ContactForm',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'contact_message' => [
						'class' => 'Drupal\contact\Entity\Message',
						'storage' => 'Drupal\Core\Entity\ContentEntityNullStorage',
					],
					'content_moderation_state' => [
						'class' => 'Drupal\content_moderation\Entity\ContentModerationState',
						'storage' => 'Drupal\Core\Entity\Sql\SqlContentEntityStorage',
					],
					'editor' => [
						'class' => 'Drupal\editor\Entity\Editor',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'field_config' => [
						'class' => 'Drupal\field\Entity\FieldConfig',
						'storage' => 'Drupal\field\FieldConfigStorage',
					],
					'field_storage_config' => [
						'class' => 'Drupal\field\Entity\FieldStorageConfig',
						'storage' => 'Drupal\field\FieldStorageConfigStorage',
					],
					'file' => ['class' => 'Drupal\file\Entity\File', 'storage' => 'Drupal\file\FileStorage'],
					'filter_format' => [
						'class' => 'Drupal\filter\Entity\FilterFormat',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'image_style' => [
						'class' => 'Drupal\image\Entity\ImageStyle',
						'storage' => 'Drupal\image\ImageStyleStorage',
					],
					'imce_profile' => [
						'class' => 'Drupal\imce\Entity\ImceProfile',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'configurable_language' => [
						'class' => 'Drupal\language\Entity\ConfigurableLanguage',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'language_content_settings' => [
						'class' => 'Drupal\language\Entity\ContentLanguageSettings',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'media_type' => [
						'class' => 'Drupal\media\Entity\MediaType',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'media' => ['class' => 'Drupal\media\Entity\Media', 'storage' => 'Drupal\media\MediaStorage'],
					'menu_link_content' => [
						'class' => 'Drupal\menu_link_content\Entity\MenuLinkContent',
						'storage' => '\Drupal\menu_link_content\MenuLinkContentStorage',
					],
					'metatag_defaults' => [
						'class' => 'Drupal\metatag\Entity\MetatagDefaults',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'node_type' => [
						'class' => 'Drupal\node\Entity\NodeType',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'node' => ['class' => 'Drupal\node\Entity\Node', 'storage' => 'Drupal\node\NodeStorage'],
					'path_alias' => [
						'class' => 'Drupal\path_alias\Entity\PathAlias',
						'storage' => 'Drupal\path_alias\PathAliasStorage',
					],
					'rdf_mapping' => [
						'class' => 'Drupal\rdf\Entity\RdfMapping',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'responsive_image_style' => [
						'class' => 'Drupal\responsive_image\Entity\ResponsiveImageStyle',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'search_page' => [
						'class' => 'Drupal\search\Entity\SearchPage',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'search_api_server' => [
						'class' => 'Drupal\search_api\Entity\Server',
						'storage' => 'Drupal\search_api\Entity\SearchApiConfigEntityStorage',
					],
					'search_api_index' => [
						'class' => 'Drupal\search_api\Entity\Index',
						'storage' => 'Drupal\search_api\Entity\SearchApiConfigEntityStorage',
					],
					'search_api_task' => [
						'class' => 'Drupal\search_api\Entity\Task',
						'storage' => 'Drupal\Core\Entity\Sql\SqlContentEntityStorage',
					],
					'shortcut_set' => [
						'class' => 'Drupal\shortcut\Entity\ShortcutSet',
						'storage' => 'Drupal\shortcut\ShortcutSetStorage',
					],
					'shortcut' => [
						'class' => 'Drupal\shortcut\Entity\Shortcut',
						'storage' => 'Drupal\Core\Entity\Sql\SqlContentEntityStorage',
					],
					'action' => [
						'class' => 'Drupal\system\Entity\Action',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'menu' => ['class' => 'Drupal\system\Entity\Menu', 'storage' => 'Drupal\system\MenuStorage'],
					'taxonomy_term' => ['class' => 'Drupal\taxonomy\Entity\Term', 'storage' => 'Drupal\taxonomy\TermStorage'],
					'taxonomy_vocabulary' => [
						'class' => 'Drupal\taxonomy\Entity\Vocabulary',
						'storage' => 'Drupal\taxonomy\VocabularyStorage',
					],
					'tour' => [
						'class' => 'Drupal\tour\Entity\Tour',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'user' => ['class' => 'Drupal\user\Entity\User', 'storage' => 'Drupal\user\UserStorage'],
					'user_role' => ['class' => 'Drupal\user\Entity\Role', 'storage' => 'Drupal\user\RoleStorage'],
					'webform' => [
						'class' => 'Drupal\webform\Entity\Webform',
						'storage' => '\Drupal\webform\WebformEntityStorage',
					],
					'webform_submission' => [
						'class' => 'Drupal\webform\Entity\WebformSubmission',
						'storage' => 'Drupal\webform\WebformSubmissionStorage',
					],
					'webform_options' => [
						'class' => 'Drupal\webform\Entity\WebformOptions',
						'storage' => '\Drupal\webform\WebformOptionsStorage',
					],
					'workflow' => [
						'class' => 'Drupal\workflows\Entity\Workflow',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'pathauto_pattern' => [
						'class' => 'Drupal\pathauto\Entity\PathautoPattern',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'view' => [
						'class' => 'Drupal\views\Entity\View',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'date_format' => [
						'class' => 'Drupal\Core\Datetime\Entity\DateFormat',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'entity_form_mode' => [
						'class' => 'Drupal\Core\Entity\Entity\EntityFormMode',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'entity_view_display' => [
						'class' => 'Drupal\layout_builder\Entity\LayoutBuilderEntityViewDisplay',
						'storage' => 'Drupal\layout_builder\Entity\LayoutBuilderEntityViewDisplayStorage',
					],
					'entity_form_display' => [
						'class' => 'Drupal\Core\Entity\Entity\EntityFormDisplay',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'entity_view_mode' => [
						'class' => 'Drupal\Core\Entity\Entity\EntityViewMode',
						'storage' => 'Drupal\Core\Config\Entity\ConfigEntityStorage',
					],
					'base_field_override' => [
						'class' => 'Drupal\Core\Field\Entity\BaseFieldOverride',
						'storage' => 'Drupal\Core\Field\BaseFieldOverrideStorage',
					],
				],
			],
			'phpunit' => ['convertUnionToIntersectionType' => true],
			'drupalRoot' => 'drupal/web',
			'tmpDir' => '/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/var/phpstan',
			'debugMode' => true,
			'productionMode' => false,
			'tempDir' => '/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/var/phpstan',
			'rootDir' => '/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan',
			'currentWorkingDirectory' => '/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal',
			'cliArgumentsVariablesRegistered' => true,
			'additionalConfigFiles' => [
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/conf/config.level0.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../composer/composer/phpstan/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../composer/pcre/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../mglaman/phpstan-drupal/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../../mglaman/phpstan-drupal/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../phpstan-deprecation-rules/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../phpstan-phpunit/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/extension-installer/src/../../phpstan-phpunit/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/../phpstan-basic.neon',
			],
			'allConfigFiles' => [
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/conf/parametersSchema.neon',
				'phar:///Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan/phpstan.phar/conf/config.level0.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/composer/composer/phpstan/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/composer/pcre/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/mglaman/phpstan-drupal/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-deprecation-rules/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/extension.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal/vendor/phpstan/phpstan-phpunit/rules.neon',
				'/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/phpstan-basic.neon',
			],
			'composerAutoloaderProjectPaths' => ['/Users/jur/www/git-projects/dxpr/8/analyze_ai_content_security_audit/drupal'],
			'generateBaselineFile' => null,
			'usedLevel' => '0',
			'cliAutoloadFile' => null,
			'env' => [
				'TERM_PROGRAM' => 'Apple_Terminal',
				'SHELL' => '/bin/zsh',
				'TERM' => 'xterm-256color',
				'TMPDIR' => '/var/folders/yj/nqydv9h90cl9n4q408l6z_1c0000gn/T/',
				'TERM_PROGRAM_VERSION' => '453',
				'TERM_SESSION_ID' => 'AA84133A-98DA-4A67-8EFB-BDB4F0ADA143',
				'USER' => 'jur',
				'SSH_AUTH_SOCK' => '/private/tmp/com.apple.launchd.jUlLWxlMd0/Listeners',
				'PATH' => '/opt/homebrew/opt/postgresql@17/bin:/Users/jur/anaconda3/bin:/Users/jur/anaconda3/condabin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/System/Cryptexes/App/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin:/var/run/com.apple.security.cryptexd/codex.system/bootstrap/usr/local/bin:/var/run/com.apple.security.cryptexd/codex.system/bootstrap/usr/bin:/var/run/com.apple.security.cryptexd/codex.system/bootstrap/usr/appleinternal/bin:/Users/jur/.composer/vendor/bin:/Users/jur/.local/bin:/Users/jur/.orbstack/bin:/Users/jur/.local/bin',
				'__CFBundleIdentifier' => 'com.apple.Terminal',
				'PWD' => '/Users/jur/www/git-projects/dxpr/8/project-groups/analyze-group/analyze_ai_content_security_audit/drupal',
				'XPC_FLAGS' => '0x0',
				'XPC_SERVICE_NAME' => '0',
				'SHLVL' => '2',
				'HOME' => '/Users/jur',
				'LOGNAME' => 'jur',
				'OLDPWD' => '/Users/jur/www/git-projects/dxpr/8/project-groups/analyze-group/analyze_ai_content_security_audit',
				'HOMEBREW_PREFIX' => '/opt/homebrew',
				'HOMEBREW_CELLAR' => '/opt/homebrew/Cellar',
				'HOMEBREW_REPOSITORY' => '/opt/homebrew',
				'INFOPATH' => '/opt/homebrew/share/info:/opt/homebrew/share/info:',
				'CONDA_EXE' => '/Users/jur/anaconda3/bin/conda',
				'_CE_M' => '',
				'_CE_CONDA' => '',
				'CONDA_PYTHON_EXE' => '/Users/jur/anaconda3/bin/python',
				'CONDA_SHLVL' => '1',
				'CONDA_PREFIX' => '/Users/jur/anaconda3',
				'CONDA_DEFAULT_ENV' => 'base',
				'CONDA_PROMPT_MODIFIER' => '(base) ',
				'GSETTINGS_SCHEMA_DIR_CONDA_BACKUP' => '',
				'GSETTINGS_SCHEMA_DIR' => '/Users/jur/anaconda3/share/glib-2.0/schemas',
				'LC_CTYPE' => 'UTF-8',
				'__CF_USER_TEXT_ENCODING' => '0x1F5:0x0:0x0',
				'COREPACK_ENABLE_AUTO_PIN' => '0',
				'NoDefaultCurrentDirectoryInExePath' => '1',
				'CLAUDE_CODE_ENTRYPOINT' => 'cli',
				'OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE' => 'delta',
				'GIT_EDITOR' => 'true',
				'CLAUDECODE' => '1',
				'_' => '/Users/jur/www/git-projects/dxpr/8/project-groups/analyze-group/analyze_ai_content_security_audit/drupal/./vendor/bin/phpstan',
				'LINES' => '50',
				'COLUMNS' => '80',
				'SHELL_VERBOSITY' => '0',
			],
		];
	}


	protected function getDynamicParameter($key)
	{
		switch (true) {
			case $key === 'singleReflectionFile': return null;
			case $key === 'singleReflectionInsteadOfFile': return null;
			case $key === 'analysedPaths': return null;
			case $key === 'analysedPathsFromConfig': return null;
			case $key === 'sysGetTempDir': return sys_get_temp_dir();
			case $key === 'pro': return [
			'dnsServers' => ['1.1.1.2'],
			'tmpDir' => ($this->getParameter('sysGetTempDir')) . '/phpstan-fixer',
		];
			default: return parent::getDynamicParameter($key);
		};
	}


	public function getParameters(): array
	{
		array_map(function ($key) { $this->getParameter($key); }, [
			'singleReflectionFile',
			'singleReflectionInsteadOfFile',
			'analysedPaths',
			'analysedPathsFromConfig',
			'sysGetTempDir',
			'pro',
		]);
		return parent::getParameters();
	}
}
