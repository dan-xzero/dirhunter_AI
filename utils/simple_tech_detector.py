#!/usr/bin/env python3
"""
Simple Technology Detector

A lightweight, browser-free alternative to Wappalyzer that uses regex patterns
to identify common web technologies from HTTP response headers and HTML content.
"""

import re
import json
import requests
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

# Configure logging
logger = logging.getLogger(__name__)

# Cache file for detected technologies
CACHE_FILE = Path("db/tech_cache.json")
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
TTL = 60 * 60 * 24  # 24 hours

# Technology detection patterns
TECH_PATTERNS = {
    # Web Servers
    "nginx": {
        "headers": [("Server", r"nginx/?([0-9.]+)?")],
        "html": []
    },
    "Apache": {
        "headers": [("Server", r"Apache/?([0-9.]+)?")],
        "html": []
    },
    "IIS": {
        "headers": [("Server", r"Microsoft-IIS/([0-9.]+)")],
        "html": []
    },
    "LiteSpeed": {
        "headers": [("Server", r"LiteSpeed/?([0-9.]+)?")],
        "html": []
    },
    
    # Cloud Services & CDN
    "Cloudflare": {
        "headers": [
            ("Server", r"cloudflare"),
            ("CF-Ray", r".*"),
            ("cf-cache-status", r".*")
        ],
        "html": [
            r'cloudflare\.com',
            r'"__cf_"',
            r'cloudflare-static',
            r'__cfduid'
        ]
    },
    "CloudFront": {
        "headers": [("Via", r"CloudFront"), ("X-Amz-Cf-Id", r".*")],
        "html": [
            r'cloudfront\.net',
            r'd[a-z0-9]{10,}\.cloudfront\.net'
        ]
    },
    "Amazon S3": {
        "headers": [
            ("x-amz-bucket-region", r".*"),
            ("x-amz-request-id", r".*"),
            ("x-amz-id-2", r".*"),
            ("Server", r"AmazonS3")
        ],
        "html": [
            r'\.s3\.amazonaws\.com',
            r'\.s3-[a-z0-9-]+\.amazonaws\.com',
            r'//s3\.amazonaws\.com',
            r'amazonaws\.com\/.*\.s3\.amazonaws\.com',
            r's3\.console\.aws\.amazon\.com',
            r'aws-s3\.com',
            r'data-s3-bucket',
            r'x-amz-meta-',
            r'amzn\.mws\.', 
            r's3-accelerate\.amazonaws\.com'
        ]
    },
    "Amazon Web Services": {
        "headers": [
            ("X-Amzn-", r".*"),
            ("x-amz-", r".*")
        ],
        "html": [
            r'aws-sdk',
            r'aws\.amazon\.com',
            r'awsstatic\.com',
            r'amazonaws\.com',
            r'aws-amplify',
            r'aws4_request',
            r'aws-sdk-js'
        ]
    },
    "AWS Lambda": {
        "headers": [
            ("Via", r".*Lambda.*"),
            ("X-Amzn-Trace-Id", r".*")
        ],
        "html": [
            r'lambda\.amazonaws\.com',
            r'lambda-url\.',
            r'lambda_function'
        ]
    },
    "AWS EC2": {
        "headers": [
            ("Server", r".*EC2.*"),
            ("X-Amz-Cf-Pop", r".*")
        ],
        "html": [
            r'ec2\.amazonaws\.com',
            r'ec2-[0-9\-]+\.'
        ]
    },
    "Amazon Route 53": {
        "headers": [],
        "html": [
            r'route53\.amazonaws\.com',
            r'awsdns-[0-9]+\.',
            r'amazon-route53'
        ]
    },
    "Fastly": {
        "headers": [
            ("Fastly-Debug-Path", r".*"),
            ("X-Served-By", r"cache-.*-fastly"),
            ("Fastly-SSL", r".*")
        ],
        "html": [
            r'fastly\.com',
            r'fastlylabs'
        ]
    },
    "Akamai": {
        "headers": [("Server", r"AkamaiGHost")],
        "html": [
            r'akamai\.net',
            r'akamaiedge\.net',
            r'akamaihd\.net'
        ]
    },
    "Cloudinary": {
        "headers": [],
        "html": [
            r'cloudinary\.com',
            r'res\.cloudinary\.com',
            r'cloudinary\.js',
            r'cloudinary-core'
        ]
    },
    "Constructor": {
        "headers": [],
        "html": [
            r'constructor\.io',
            r'constructorio',
            r'cnstrc\.com'
        ]
    },
    
    # JavaScript Frameworks
    "jQuery": {
        "headers": [],
        "html": [
            r"jquery[.-]([0-9.]+)\.(?:min\.)?js",
            r'<script[^>]*?>[^<]*?jquery.*?<\/script>',
            r'src=".*?jquery[.-]([0-9.]+)\.(?:min\.)?js',
            r'jQuery\.fn\.jquery\s*=\s*["\']([0-9.]+)["\']',
            r'/jquery@([0-9\.]+)/',
            r'jquery/([0-9\.]+)/'
        ]
    },
    "React": {
        "headers": [],
        "html": [
            r"react[.-]([0-9.]+)\.(?:min\.)?js",
            r"react-dom[.-]([0-9.]+)\.(?:min\.)?js",
            r'content="react"',
            r'ReactDOM\.render\(',
            r'__REACT_ROOT_ID__',
            r'_reactListening',
            r'react@([0-9\.]+)/',
            r'react-dom@',
            r'ReactDOM\.',
            r'React\.createElement'
        ]
    },
    "React Router": {
        "headers": [],
        "html": [
            r'react-router',
            r'react-router-dom',
            r'createBrowserRouter',
            r'BrowserRouter',
            r'react-router@([0-9\.]+)/',
            r'react-router-dom@([0-9\.]+)/'
        ]
    },
    "Angular": {
        "headers": [],
        "html": [
            r"angular[.-]([0-9.]+)\.(?:min\.)?js",
            r'ng-app="',
            r'ng-controller="',
            r'angular\.module\(',
            r'ng-version="([0-9.]+)"',
            r'angular@([0-9\.]+)/'
        ]
    },
    "Vue.js": {
        "headers": [],
        "html": [
            r"vue[.-]([0-9.]+)\.(?:min\.)?js",
            r'content="vue"',
            r'new Vue\({',
            r'v-[a-z]+',
            r'"vuex":', 
            r'vue@([0-9\.]+)/',
            r'__vue__'
        ]
    },
    "Ember.js": {
        "headers": [],
        "html": [
            r"ember[.-]([0-9.]+)\.(?:min\.)?js",
            r"ember-data[.-]([0-9.]+)\.(?:min\.)?js",
            r'ember-view',
            r'_emberENV'
        ]
    },
    "Svelte": {
        "headers": [],
        "html": [
            r"svelte[.-]([0-9.]+)\.(?:min\.)?js",
            r'__SVELTE__',
            r'svelte-[a-z0-9]+',
            r'svelte@([0-9\.]+)/'
        ]
    },
    "Next.js": {
        "headers": [],
        "html": [
            r'__NEXT_DATA__',
            r'"buildId"',
            r'next/dist/shared/lib/head',
            r'next\.js.*?([0-9.]+)',
            r'"nextExport"',
            r'next/([0-9\.]+)/',
            r'next@([0-9\.]+)/',
            r'"__next"'
        ]
    },
    "Nuxt.js": {
        "headers": [],
        "html": [
            r'__NUXT__',
            r'"nuxt"',
            r'nuxtjs',
            r'window\.__NUXT__',
            r'nuxt@([0-9\.]+)/'
        ]
    },
    "Preact": {
        "headers": [],
        "html": [
            r'preact',
            r'preactjs',
            r'preact-render-to-string',
            r'preact@([0-9\.]+)/'
        ]
    },
    "core-js": {
        "headers": [],
        "html": [
            r'core-js/modules',
            r'/core-js@([0-9.]+)/',
            r'core-js\/([0-9.]+)\/',
            r'es\.[a-z]+\.js'
        ]
    },
    "styled-components": {
        "headers": [],
        "html": [
            r'styled-components',
            r'sc-[a-zA-Z0-9]{5,}',
            r'styled-components@([0-9\.]+)/',
            r'_styled-components'
        ]
    },
    "Swiper": {
        "headers": [],
        "html": [
            r'swiper',
            r'swiper\.js',
            r'swiper@([0-9\.]+)/',
            r'swiper/([0-9\.]+)/',
            r'swiper-container'
        ]
    },
    
    # CMS
    "WordPress": {
        "headers": [],
        "html": [
            r"wp-content",
            r"wp-includes",
            r"WordPress\/([0-9.]+)",
            r'content="WordPress',
            r'name="generator" content="WordPress ([0-9.]+)"',
            r'wp-embed\.min\.js',
            r'wp-emoji',
            r'wp-json',
            r'wp-block-'
        ]
    },
    "Drupal": {
        "headers": [],
        "html": [
            r'<meta name="Generator" content="Drupal ([0-9.]+)"',
            r'name="drupal-cache"',
            r'jQuery\.extend\(Drupal',
            r'data-drupal-',
            r'drupal\.org',
            r'/sites/default/files',
            r'/core/misc/drupal'
        ]
    },
    "Joomla": {
        "headers": [],
        "html": [
            r'<meta name="generator" content="Joomla! ([0-9.]+)"',
            r'/components/com_',
            r'/templates/(?:system|joomla)/',
            r'joomla',
            r'/media/jui/',
            r'/media/system/js/core'
        ]
    },
    "Wix": {
        "headers": [],
        "html": [
            r'X-Wix-Published-Version',
            r'X-Wix-Request-Id',
            r'wix\.com',
            r'wixstatic\.com',
            r'wix-viewer',
            r'wixsite'
        ]
    },
    "Ghost": {
        "headers": [],
        "html": [
            r'content="Ghost ([0-9.]+)"',
            r'ghost\.org',
            r'ghost-theme',
            r'ghost\/[a-z]',
            r'/assets/built/ghost'
        ]
    },
    "Squarespace": {
        "headers": [],
        "html": [
            r'squarespace\.com',
            r'static\.squarespace\.com',
            r'squarespace-gallery',
            r'data-static-squarespace',
            r'static1\.squarespace'
        ]
    },
    "Format": {
        "headers": [],
        "html": [
            r'format\.com',
            r'formatcdn\.com',
            r'format-assets',
            r'format\.js'
        ]
    },
    
    # E-commerce
    "Magento": {
        "headers": [],
        "html": [
            r'<script[^>]+?Mage\.Cookies',
            r'var BLANK_URL = \'(?:.*)\/js\/blank.html\'',
            r'var BLANK_IMG = \'(?:.*)\/js\/spacer.gif\'',
            r'var Mage = {',
            r'magento\.com',
            r'/skin/frontend/',
            r'Mage_Core'
        ]
    },
    "WooCommerce": {
        "headers": [],
        "html": [
            r"woocommerce[.-]([0-9.]+)\.(?:min\.)?js",
            r'content="WooCommerce"',
            r'class="woocommerce',
            r'wc-block-',
            r'data-woocommerce-version="([0-9.]+)"',
            r'wc-api',
            r'woocommerce-'
        ]
    },
    "Shopify": {
        "headers": [],
        "html": [
            r'cdn\.shopify\.com',
            r'Shopify\.(?:shop|currency)',
            r'shopify-(?:section|payment)-button',
            r'_shopify_',
            r'ShopifyAnalytics',
            r'shopify\.',
            r'shopifycdn\.com'
        ]
    },
    "PrestaShop": {
        "headers": [],
        "html": [
            r'prestashop',
            r'prestashop-theme',
            r'prestashop\.com',
            r'content="PrestaShop ([0-9.]+)"',
            r'/themes/[^/]+/assets',
            r'var prestashop'
        ]
    },
    "OpenCart": {
        "headers": [],
        "html": [
            r'opencart',
            r'index.php\?route=',
            r'catalog\/view\/theme',
            r'content="OpenCart ([0-9.]+)"',
            r'/catalog/view/javascript/'
        ]
    },
    "Cart Functionality": {
        "headers": [],
        "html": [
            r'shopping-cart',
            r'add-to-cart',
            r'cart\.js',
            r'\/cart\/',
            r'checkout',
            r'viewcart',
            r'cartpage'
        ]
    },
    "Yotpo Reviews": {
        "headers": [],
        "html": [
            r'yotpo',
            r'yotpo\.com',
            r'yotpo-widget',
            r'staticw2\.yotpo\.com',
            r'yotpocdn'
        ]
    },
    "LiveIntent": {
        "headers": [],
        "html": [
            r'liadm\.com',
            r'liveintent\.com',
            r'liveintent',
            r'LiveIntentTag'
        ]
    },
    "Datadog": {
        "headers": [],
        "html": [
            r'datadoghq\.com',
            r'datadog-rum',
            r'DD_RUM',
            r'datadoghq-browser-agent'
        ]
    },
    "Impact": {
        "headers": [],
        "html": [
            r'impact\.com',
            r'impactradius',
            r'ire-tracking',
            r'trackimpression'
        ]
    },
    "Tatari": {
        "headers": [],
        "html": [
            r'tatari\.tv',
            r'tataritracking',
            r'tatari_init'
        ]
    },
    
    # API/GraphQL
    "GraphQL": {
        "headers": [],
        "html": [
            r'<title>GraphiQL',
            r'/graphql',
            r'graphql-playground',
            r'__APOLLO_STATE__',
            r'graphqlHTTP',
            r'operationName',
            r'graphql/query'
        ]
    },
    "REST API": {
        "headers": [],
        "html": [
            r'api/v[0-9]',
            r'application/json',
            r'application/hal\\+json',
            r'swagger-ui',
            r'api-docs',
            r'/api/[a-zA-Z0-9]+/',
            r'rest-api'
        ]
    },
    "Apollo": {
        "headers": [],
        "html": [
            r'apollo-client',
            r'__APOLLO_STATE__',
            r'apollo[.-]([0-9.]+)\.(?:min\.)?js',
            r'apollographql',
            r'apollo@([0-9\.]+)/',
            r'apolloClient'
        ]
    },
    "Algolia": {
        "headers": [],
        "html": [
            r'algoliasearch',
            r'algolia\.com',
            r'algolianet\.com',
            r'instantsearch\.js',
            r'algoliasearch\.min\.js',
            r'algolia-client',
            r'algolia@([0-9\.]+)/'
        ]
    },
    
    # HTTP Features
    "HTTP/2": {
        "headers": [
            ("X-Firefox-Spdy", r"h2"), 
            ("x-amzn-http", r"2")
        ],
        "html": []
    },
    "HTTP/3": {
        "headers": [("Alt-Svc", r"h3=")],
        "html": []
    },
    
    # Security
    "Content-Security-Policy": {
        "headers": [("Content-Security-Policy", r".*")],
        "html": []
    },
    "HSTS": {
        "headers": [("Strict-Transport-Security", r".*")],
        "html": []
    },
    "JWT": {
        "headers": [],
        "html": [
            r'jwt',
            r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            r'jsonwebtoken',
            r'token='
        ]
    },
    "OAuth": {
        "headers": [],
        "html": [
            r'oauth',
            r'authorize\?client_id=',
            r'oauth2',
            r'openid',
            r'/oauth/token'
        ]
    },
    "reCAPTCHA": {
        "headers": [],
        "html": [
            r'www\.google\.com/recaptcha/api\.js',
            r'class="g-recaptcha"',
            r'grecaptcha',
            r'recaptcha'
        ]
    },
    "ModSecurity": {
        "headers": [("X-Mod-Security", r".*")],
        "html": []
    },
    "Auth0": {
        "headers": [],
        "html": [
            r'auth0\.com',
            r'auth0\.js',
            r'Auth0Lock',
            r'auth0-js',
            r'auth0@([0-9\.]+)/'
        ]
    },
    "TrustArc": {
        "headers": [],
        "html": [
            r'trustarc\.com',
            r'truste\.com',
            r'truste-svc\.net',
            r'trustarc',
            r'trustedsite'
        ]
    },
    
    # Analytics & Marketing
    "Google Analytics": {
        "headers": [],
        "html": [
            r'google-analytics\.com/analytics\.js',
            r'gtag\(',
            r'ga\(',
            r'GoogleAnalyticsObject',
            r'UA-[0-9]+-[0-9]+',
            r'G-[A-Z0-9]+', # GA4
            r'google-analytics\.com/g/collect', # GA4
            r'analytics\.js'
        ]
    },
    "Google Tag Manager": {
        "headers": [],
        "html": [
            r'googletagmanager\.com',
            r'gtm\.js',
            r'GTM-[A-Z0-9]+',
            r'dataLayer',
            r'googletagmanager',
            r'gtm_auth'
        ]
    },
    "Adobe Analytics": {
        "headers": [],
        "html": [
            r'adobe\.com/analytics',
            r'AdobeAnalytics',
            r's\.trackingServer',
            r's_code\.js',
            r'omniture',
            r'sc\.omtrdc\.net'
        ]
    },
    "Facebook Pixel": {
        "headers": [],
        "html": [
            r'connect\.facebook\.net',
            r'fbq\(',
            r'fbevents\.js',
            r'_fbq',
            r'facebook-pixel',
            r'facebook-jssdk'
        ]
    },
    "Snowplow Analytics": {
        "headers": [],
        "html": [
            r'snowplow',
            r'sp\.js',
            r'snowplowTracker',
            r'snowplow-analytics',
            r'snowplowv2',
            r'snowplow@([0-9\.]+)/',
            r'"spSiteConfigUrl"',
            r'snowplowClientSessionUserId',
            r'iglu:',
            r'sp\.js\?sp=',
            r'new GlobalSnowplowNamespace'
        ]
    },
    "DoubleClick Floodlight": {
        "headers": [],
        "html": [
            r'doubleclick\.net/activity',
            r'dc_lat=',
            r'googleads\.g\.doubleclick\.net',
            r'floodlight',
            r'doubleclick'
        ]
    },
    "Microsoft Advertising": {
        "headers": [],
        "html": [
            r'bat\.bing\.com',
            r'microsoftonline\.com',
            r'clarity\.ms',
            r'microsoft\.com/ads',
            r'msadcenter',
            r'uetq',
            r'msclkid=',
            r'ms:pageview',
            r'microsoftads',
            r'microsoft\.com/advertising'
        ]
    },
    "Microsoft Clarity": {
        "headers": [],
        "html": [
            r'clarity\.ms',
            r'clarity\.js',
            r'clarity-[a-z]+',
            r'clarityAutoCapture',
            r'clarity/tag/([0-9\.]+)',
            r'c\.clarity\.ms',
            r'msclarity',
            r'window\.clarity',
            r'clarity=',
            r'clarityconfig'
        ]
    },
    "Criteo": {
        "headers": [],
        "html": [
            r'criteo\.com',
            r'criteo\.net',
            r'criteo_q',
            r'criteo\.',
            r'static\.criteo\.net'
        ]
    },
    "Pinterest Ads": {
        "headers": [],
        "html": [
            r'pintrk',
            r'pinterest-tag',
            r'ct\.pinterest\.com',
            r'pinterest\.com/pin/create',
            r'pinterest-track'
        ]
    },
    "Pinterest Conversion Tag": {
        "headers": [],
        "html": [
            r'pinterest/ft\.js',
            r'ct\.pinterest\.com',
            r'pinterest_conversion_id',
            r'pinterestConversion'
        ]
    },
    "LinkedIn Insight Tag": {
        "headers": [],
        "html": [
            r'linkedin\.com/insight',
            r'_linkedin_data_partner_id',
            r'linkedin_partner_id',
            r'snap\.licdn\.com',
            r'linkedin\.com/px',
            r'linkedin_pixel_',
            r'litrk',
            r'_linkedin_partner_id'
        ]
    },
    "Reddit Ads": {
        "headers": [],
        "html": [
            r'reddit\.com/pixel',
            r'rdt_uuid',
            r'redditpixel',
            r'reddit_pixel'
        ]
    },
    "TikTok Pixel": {
        "headers": [],
        "html": [
            r'tiktok\.com/pixel',
            r'ttq\.',
            r'tiktok-pixel',
            r'tiktokcdn',
            r'tiktok\.com/i18n',
            r'bytedance',
            r'ttwid',
            r'TiktokAnalyticsObject'
        ]
    },
    "Attentive": {
        "headers": [],
        "html": [
            r'attentive\.com',
            r'attentivemobile',
            r'attn-',
            r'attn\.tv',
            r'attentive'
        ]
    },
    "AppNexus": {
        "headers": [],
        "html": [
            r'adnxs\.com',
            r'appnexus',
            r'prebid',
            r'xandr\.com',
            r'appnexusrtb'
        ]
    },
    "PebblePost": {
        "headers": [],
        "html": [
            r'pebblepost\.com',
            r'pbbl\.co',
            r'pebblepost',
            r'pbblx1\.com'
        ]
    },
    
    # CDN Libraries
    "cdnjs": {
        "headers": [],
        "html": [
            r'cdnjs\.cloudflare\.com',
            r'cdnjs\.com',
            r'/cdnjs/',
            r'cdnjs\.'
        ]
    },
    "Google Font API": {
        "headers": [],
        "html": [
            r'fonts\.googleapis\.com',
            r'fonts\.gstatic\.com',
            r'fonts\.google\.com',
            r'googlefonts',
            r'google\.com/fonts'
        ]
    },
    "Twitter Emoji (Twemoji)": {
        "headers": [],
        "html": [
            r'twemoji',
            r'twitter-emoji',
            r'twimg\.com/emoji',
            r'twemoji\.js',
            r'twemoji\.min\.js'
        ]
    },
    
    # Languages/Platforms
    "PHP": {
        "headers": [("X-Powered-By", r"PHP/?([0-9.]+)?")],
        "html": [
            r'\.php\b',
            r'<\?php',
            r'/php/',
            r'php\.ini'
        ]
    },
    "ASP.NET": {
        "headers": [
            ("X-AspNet-Version", r"([0-9.]+)?"), 
            ("X-Powered-By", r"ASP\.NET")
        ],
        "html": [
            r'\.aspx\b',
            r'__VIEWSTATE',
            r'__EVENTVALIDATION',
            r'asp\.net',
            r'\.asp$'
        ]
    },
    "Node.js": {
        "headers": [],
        "html": [
            r'node_modules',
            r'express',
            r'socketio',
            r'node\.js',
            r'nodejs',
            r'/node/'
        ]
    },
    "Python": {
        "headers": [("X-Powered-By", r"Python/?([0-9.]+)?")],
        "html": [
            r'\.py\b',
            r'django',
            r'flask',
            r'python\.org',
            r'__pycache__',
            r'/python/'
        ]
    },
    "Ruby on Rails": {
        "headers": [
            ("X-Powered-By", r"Phusion Passenger"), 
            ("Server", r"Passenger"), 
            ("X-Runtime", r".*"),
            ("X-Request-Id", r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
            ("X-Rack-Cache", r".*")
        ],
        "html": [
            r'rails',
            r'data-turbolinks',
            r'rubyonrails\.org',
            r'rails-ujs',
            r'/rails/',
            r'asset-pipeline',
            r'csrf-token',
            r'method="post"><input name="_method" type="hidden" value="',
            r'value="rails-csrf"',
            r'authenticity_token',
            r'ruby-on-rails',
            r'rails-env',
            r'data-remote="true"',
            r'ruby on rails',
            r'assets/application-[a-z0-9]+'
        ]
    },
    "Ruby": {
        "headers": [
            ("Server", r".*\(Ruby\).*"),
            ("X-Rack-Cache", r".*")
        ],
        "html": [
            r'\.rb\b',
            r'ruby',
            r'rubygems',
            r'ruby-lang',
            r'\.bundle/',
            r'ruby/',
            r'gems/',
            r'Bundler\.require',
            r'RubyGems',
            r'ruby_version',
            r'rubyforge',
            r'rbenv',
            r'rvm'
        ]
    },
    "Java": {
        "headers": [("X-Powered-By", r"JSP/?([0-9.]+)?")],
        "html": [
            r'\.jsp\b',
            r'java\.com',
            r'jakarta',
            r'jsessionid',
            r'/java/',
            r'servlet'
        ]
    },
    "Go": {
        "headers": [],
        "html": [
            r'go-version',
            r'golang',
            r'go\.dev',
            r'gorouter'
        ]
    },
    "Rust": {
        "headers": [],
        "html": [
            r'rustlang',
            r'rust-lang',
            r'crates\.io',
            r'\.rs$'
        ]
    },
    
    # Frontend Frameworks
    "Bootstrap": {
        "headers": [],
        "html": [
            r"bootstrap[.-]([0-9.]+)\.(?:min\.)?(?:css|js)",
            r'content="Bootstrap ([0-9.]+)"',
            r'class="(?:.*?)(?:btn|modal|navbar|container|row|col-)',
            r'bootstrap@([0-9\.]+)/',
            r'bootstrap/([0-9\.]+)/'
        ]
    },
    "Tailwind": {
        "headers": [],
        "html": [
            r'tailwind[.-]([0-9.]+)\.(?:min\.)?css',
            r'tailwindcss',
            r'class="(?:[a-z0-9:-]+\s+)*(?:bg-|text-|p-|m-|flex|grid|border-)',
            r'tailwindcss@',
            r'tailwind/([0-9\.]+)/'
        ]
    },
    "Material-UI": {
        "headers": [],
        "html": [
            r'material-ui',
            r'mui\.com',
            r'@material-ui',
            r'MuiButton',
            r'materialui'
        ]
    },
    "Foundation": {
        "headers": [],
        "html": [
            r'foundation\.zurb',
            r'foundation[.-]([0-9.]+)\.(?:min\.)?js',
            r'foundation-sites',
            r'foundation/([0-9\.]+)/'
        ]
    },
    
    # Package Managers
    "NPM": {
        "headers": [],
        "html": [
            r'node_modules',
            r'package\.json',
            r'npm install',
            r'npmjs\.com',
            r'npm/'
        ]
    },
    "Yarn": {
        "headers": [],
        "html": [
            r'yarnpkg',
            r'yarn add',
            r'yarn\.lock',
            r'yarn/'
        ]
    },
    
    # Databases (frontend clues)
    "MongoDB": {
        "headers": [],
        "html": [
            r'mongodb',
            r'mongoose',
            r'mongodb\.com',
            r'mongo/'
        ]
    },
    "MySQL": {
        "headers": [],
        "html": [
            r'mysql',
            r'mysqli',
            r'mysql\.com',
            r'mysql_'
        ]
    },
    "PostgreSQL": {
        "headers": [],
        "html": [
            r'postgresql',
            r'postgres',
            r'pgsql',
            r'pg_'
        ]
    },
    
    # Build Tools
    "Webpack": {
        "headers": [],
        "html": [
            r'webpack',
            r'__webpack_require__',
            r'webpack[.-]([0-9.]+)\.(?:min\.)?js',
            r'webpack@([0-9\.]+)/',
            r'webpack/([0-9\.]+)/',
            r'webpackJsonp'
        ]
    },
    "Babel": {
        "headers": [],
        "html": [
            r'babel',
            r'babelrc',
            r'babel[.-]([0-9.]+)\.(?:min\.)?js',
            r'babel-polyfill',
            r'babel-runtime'
        ]
    },
    
    # Security Vulnerabilities (specific indicators)
    "Log4j": {
        "headers": [],
        "html": [
            r'log4j',
            r'log4j\.properties',
            r'log4j[.-]([0-9.]+)\.(?:min\.)?js',
            r'log4j-api'
        ]
    },
    "Spring": {
        "headers": [],
        "html": [
            r'springframework',
            r'spring-boot',
            r'spring\.io',
            r'@SpringBootApplication',
            r'spring/([0-9\.]+)/'
        ]
    },
    "Struts": {
        "headers": [],
        "html": [
            r'struts',
            r'struts\.apache\.org',
            r'org\.apache\.struts',
            r'struts\.xml',
            r'struts2'
        ]
    },
    
    # Meta/SEO
    "Open Graph": {
        "headers": [],
        "html": [
            r'property="og:',
            r'meta property="og:',
            r'name="og:',
            r'og:image',
            r'og:url'
        ]
    },
    "Priority Hints": {
        "headers": [],
        "html": [
            r'fetchpriority=',
            r'importance=',
            r'fetchPriority',
            r'loading="lazy"'
        ]
    },
    
    # Other
    "RSS": {
        "headers": [],
        "html": [
            r'application/rss\+xml',
            r'<link [^>]*type="application/rss\+xml"',
            r'rss\.xml',
            r'rss+xml',
            r'/feed/'
        ]
    },
    "Gutenberg": {
        "headers": [],
        "html": [
            r'wp-block-',
            r'wp-blocks',
            r'gutenberg',
            r'gutenberg/([0-9\.]+)/',
            r'wp-editor'
        ]
    },
    "Gladly": {
        "headers": [],
        "html": [
            r'gladly\.com',
            r'gladlyinc',
            r'gladly-chat',
            r'gladly\.'
        ]
    }
}

# Add new patterns for additional technologies
TECH_PATTERNS.update({
    # Cloud Platforms
    "Google Cloud Platform": {
        "headers": [
            (re.compile(r"x-goog-|x-gcp-", re.I), None)
        ],
        "html": [
            (re.compile(r'googletagmanager\.com/ns\.html.*[?&]id=GTM-', re.I), None),
            (re.compile(r'storage\.googleapis\.com|cloudfront\.net/gcp', re.I), None)
        ],
        "meta": "Google Cloud Platform - Suite of cloud computing services by Google."
    },
    "Microsoft Azure": {
        "headers": [
            (re.compile(r"x-ms-|x-azure-", re.I), None)
        ],
        "html": [
            (re.compile(r'azure\.microsoft\.com|\.azureedge\.net|\.windowsazure\.com', re.I), None)
        ],
        "meta": "Microsoft Azure - Cloud computing service by Microsoft."
    },
    "IBM Cloud": {
        "headers": [
            (re.compile(r"x-powered-by:.*IBM", re.I), None)
        ],
        "html": [
            (re.compile(r'cloud\.ibm\.com|softlayer\.net|bluemix\.net', re.I), None)
        ],
        "meta": "IBM Cloud - Cloud computing services by IBM."
    },
    
    # JavaScript Frameworks/Libraries
    "Preact": {
        "headers": [],
        "html": [
            (re.compile(r'preact\.(?:min\.)?js|preactjs', re.I), None),
            (re.compile(r'"preact"|preact\.h|preact\.render', re.I), None),
            (re.compile(r'from\s+["\']preact["\']|import\s+(?:\{\s*)?(?:h|render|Component)(?:\s*\})?\s+from\s+["\']preact["\']', re.I), None)
        ],
        "meta": "Preact - Fast 3kB alternative to React with the same modern API."
    },
    "Alpine.js": {
        "headers": [],
        "html": [
            (re.compile(r'alpine(?:\.min)?\.js', re.I), lambda match, content: re.search(r'alpine(?:\.min)?\.js.*?([0-9.]+)', content)),
            (re.compile(r'[\'"][xv]-data|x-init|x-bind|x-on|x-text|x-html|x-show|x-cloak|x-ref|x-if|x-for|x-transition|x-spread|x-modelable|alpine\.js', re.I), None)
        ],
        "meta": "Alpine.js - A rugged, minimal tool for composing behavior directly in your markup."
    },
    "htmx": {
        "headers": [],
        "html": [
            (re.compile(r'htmx(?:\.min)?\.js', re.I), lambda match, content: re.search(r'htmx(?:\.min)?\.js.*?([0-9.]+)', content)),
            (re.compile(r'[\'"]hx-[a-z]|hx-boost|hx-get|hx-post|hx-put|hx-delete|hx-swap|hx-target', re.I), None)
        ],
        "meta": "htmx - High power tools for HTML."
    },
    
    # Performance & Analytics
    "Web Vitals": {
        "headers": [],
        "html": [
            (re.compile(r'webVitals|web-vitals\.js|getCLS\(\)|getFID\(\)|getLCP\(\)', re.I), None)
        ],
        "meta": "Web Vitals - Essential metrics for a healthy site by Google."
    },
    "Segment": {
        "headers": [],
        "html": [
            (re.compile(r'segment\.com/analytics|analytics\.segment\.com/v1|window\.analytics|analytics\.track\(', re.I), None)
        ],
        "meta": "Segment - Customer Data Platform for collecting, cleaning, and controlling customer data."
    },
    "Mixpanel": {
        "headers": [],
        "html": [
            (re.compile(r'mixpanel\.com|mixpanel\.track|mixpanel\.identify', re.I), None)
        ],
        "meta": "Mixpanel - Product analytics for modern product teams."
    },
    
    # Progressive Web App Features
    "PWA": {
        "headers": [],
        "html": [
            (re.compile(r'<link[^>]+rel=["\'](manifest)["\']', re.I), None),
            (re.compile(r'navigator\.serviceWorker', re.I), None)
        ],
        "meta": "Progressive Web App - Web applications that are regular web pages or websites, but can appear to the user like traditional applications."
    },
    
    # E-commerce Platforms
    "Salesforce Commerce Cloud": {
        "headers": [],
        "html": [
            (re.compile(r'demandware\.com|demandware\.net|demandware\.store|dwanalytics', re.I), None)
        ],
        "meta": "Salesforce Commerce Cloud (formerly Demandware) - Cloud-based e-commerce platform."
    },
    "BigCommerce": {
        "headers": [],
        "html": [
            (re.compile(r'bigcommerce\.com|cdn\.bigcommerce\.com|mybigcommerce\.com', re.I), None)
        ],
        "meta": "BigCommerce - E-commerce platform for fast-growing and enterprise brands."
    },
    
    # Mobile Detection
    "Adaptive Design": {
        "headers": [],
        "html": [
            (re.compile(r'<meta[^>]+viewport', re.I), None),
            (re.compile(r'@media\s+(?:only\s+)?screen', re.I), None)
        ],
        "meta": "Adaptive Design - Web design approach aimed at crafting sites to provide an optimal viewing experience."
    },
    
    # Authentication
    "OAuth": {
        "headers": [
            (re.compile(r"authorization:\s*bearer\s+", re.I), None)
        ],
        "html": [
            (re.compile(r'oauth\s+|openid|auth0\.com', re.I), None)
        ],
        "meta": "OAuth - An open standard for access delegation."
    },
    
    # Internationalization
    "i18next": {
        "headers": [],
        "html": [
            (re.compile(r'i18next\.t\(|i18next(?:\.min)?\.js', re.I), None)
        ],
        "meta": "i18next - Internationalization framework for JavaScript."
    },
    
    # Accessibility
    "WAI-ARIA": {
        "headers": [],
        "html": [
            (re.compile(r'aria-[a-z]+=["\']|role=["\'][a-z-]+["\']', re.I), None)
        ],
        "meta": "WAI-ARIA - A technical specification that provides a framework to improve the accessibility and interoperability of web content and applications."
    },
    
    # Development Tools
    "Storybook": {
        "headers": [],
        "html": [
            (re.compile(r'storybook-static|\.stories\.js', re.I), None)
        ],
        "meta": "Storybook - An open source tool for developing UI components in isolation."
    },
    "Cypress": {
        "headers": [],
        "html": [
            (re.compile(r'cypress\.io|cy\.visit|cy\.get\(', re.I), None)
        ],
        "meta": "Cypress - Front end testing tool built for the modern web."
    }
})

# Import the active scanning module if available
try:
    from utils.active_scan import perform_active_scan
    ACTIVE_SCAN_AVAILABLE = True
except ImportError:
    ACTIVE_SCAN_AVAILABLE = False
    logger.warning("Active scanning module not available - using passive detection only")

# Import the false positive filter if available
try:
    from utils.false_positive_filter import filter_false_positives
    FALSE_POSITIVE_FILTER_AVAILABLE = True
except ImportError:
    FALSE_POSITIVE_FILTER_AVAILABLE = False
    logger.warning("False positive filter not available - using raw detection results")

def _load_cache() -> Dict[str, Any]:
    """Load technology cache from file"""
    try:
        return json.loads(CACHE_FILE.read_text()) if CACHE_FILE.exists() else {}
    except Exception as e:
        logger.warning(f"Failed to load tech cache: {e}")
        return {}


def _save_cache(data: Dict[str, Any]):
    """Save technology cache to file"""
    try:
        CACHE_FILE.write_text(json.dumps(data, indent=2))
    except Exception as e:
        logger.warning(f"Failed to save tech cache: {e}")


def _detect_from_response(response) -> Dict[str, Any]:
    """Detect technologies from a response object"""
    techs = {}
    headers = dict(response.headers)
    content = response.text
    
    # Check headers
    for tech_name, patterns in TECH_PATTERNS.items():
        version = None
        
        # Check headers
        for header_item in patterns["headers"]:
            if isinstance(header_item, tuple) and len(header_item) == 2:
                if isinstance(header_item[0], str):
                    # Traditional (header_name, regex_pattern) format
                    header_name, regex_pattern = header_item
                    if header_name.lower() in {k.lower() for k in page_headers.keys()}:
                        header_value = next((v for k, v in page_headers.items() 
                                          if k.lower() == header_name.lower()), "")
                        
                        if isinstance(regex_pattern, tuple):
                            pattern, extractor = regex_pattern
                        else:
                            pattern, extractor = regex_pattern, None
                            
                        # Handle compiled regex objects differently
                        if isinstance(pattern, re.Pattern):
                            match = pattern.search(header_value)
                        else:
                            match = re.search(pattern, header_value, re.IGNORECASE)
                            
                        if match:
                            version = ""
                            if extractor and callable(extractor):
                                version_match = extractor(match, header_value)
                                if version_match:
                                    version = version_match.group(1) if hasattr(version_match, 'group') else version_match
                            elif match.groups():
                                version = match.group(1)
                                
                            detected_techs[tech_name] = {"version": version, "confidence": "high", "source": "header"}
                            break
                elif isinstance(header_item[0], re.Pattern):
                    # Handle (compiled_pattern, extractor) format
                    pattern, extractor = header_item
                    
                    # Check each header against the compiled pattern
                    for header_name, header_value in page_headers.items():
                        match = pattern.search(header_name)
                        if match:
                            version = ""
                            if extractor and callable(extractor):
                                version_match = extractor(match, header_value)
                                if version_match:
                                    version = version_match.group(1) if hasattr(version_match, 'group') else version_match
                            elif match.groups():
                                version = match.group(1)
                                
                            detected_techs[tech_name] = {"version": version, "confidence": "high", "source": "header"}
                            break
        
        # If already found in headers, skip HTML check
        if tech_name in techs:
            continue
            
        # Check HTML content if available
        if content:
            for pattern in patterns["html"]:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    if match.groups() and match.group(1):
                        version = match.group(1)
                        # Clean up version string - remove any non-version characters
                        version = re.sub(r'[^0-9\.]', '', version)
                    techs[tech_name] = {"version": version} if version else {}
                    break
    
    # Enhanced version detection - look for version information elsewhere in the page
    # This is crucial for CVE matching which relies on accurate version information
    if content:
        # Special cases for common technologies
        _enhance_version_detection(techs, content)
    
    return techs

def _enhance_version_detection(techs: Dict[str, Any], content: str) -> None:
    """Enhance version detection for technologies that are already detected"""
    # WordPress
    if "WordPress" in techs and not techs["WordPress"].get("version"):
        wp_version = _extract_wordpress_version(content)
        if wp_version:
            techs["WordPress"]["version"] = wp_version
            
    # Gutenberg (WordPress editor)
    if "Gutenberg" in techs and not techs["Gutenberg"].get("version"):
        gutenberg_version = _extract_gutenberg_version(content)
        if gutenberg_version:
            techs["Gutenberg"]["version"] = gutenberg_version
    
    # jQuery
    if "jQuery" in techs and not techs["jQuery"].get("version"):
        jquery_version = _extract_jquery_version(content)
        if jquery_version:
            techs["jQuery"]["version"] = jquery_version
    
    # Bootstrap
    if "Bootstrap" in techs and not techs["Bootstrap"].get("version"):
        bootstrap_version = _extract_bootstrap_version(content)
        if bootstrap_version:
            techs["Bootstrap"]["version"] = bootstrap_version
            
    # React
    if "React" in techs and not techs["React"].get("version"):
        react_version = _extract_react_version(content)
        if react_version:
            techs["React"]["version"] = react_version
            
    # Vue.js
    if "Vue.js" in techs and not techs["Vue.js"].get("version"):
        vue_version = _extract_vue_version(content)
        if vue_version:
            techs["Vue.js"]["version"] = vue_version
            
    # Next.js
    if "Next.js" in techs and not techs["Next.js"].get("version"):
        next_version = _extract_next_version(content)
        if next_version:
            techs["Next.js"]["version"] = next_version
            
    # Microsoft Clarity
    if "Microsoft Clarity" in techs and not techs["Microsoft Clarity"].get("version"):
        clarity_version = _extract_clarity_version(content)
        if clarity_version:
            techs["Microsoft Clarity"]["version"] = clarity_version
            
    # Ruby on Rails
    if "Ruby on Rails" in techs and not techs["Ruby on Rails"].get("version"):
        rails_version = _extract_rails_version(content)
        if rails_version:
            techs["Ruby on Rails"]["version"] = rails_version
            
    # Ruby
    if "Ruby" in techs and not techs["Ruby"].get("version"):
        ruby_version = _extract_ruby_version(content)
        if ruby_version:
            techs["Ruby"]["version"] = ruby_version
            
    # core-js
    if "core-js" in techs and not techs["core-js"].get("version"):
        corejs_version = _extract_corejs_version(content)
        if corejs_version:
            techs["core-js"]["version"] = corejs_version
            
    # styled-components
    if "styled-components" in techs and not techs["styled-components"].get("version"):
        styled_version = _extract_styled_components_version(content)
        if styled_version:
            techs["styled-components"]["version"] = styled_version
            
    # Swiper
    if "Swiper" in techs and not techs["Swiper"].get("version"):
        swiper_version = _extract_swiper_version(content)
        if swiper_version:
            techs["Swiper"]["version"] = swiper_version
            
    # React Router
    if "React Router" in techs and not techs["React Router"].get("version"):
        router_version = _extract_react_router_version(content)
        if router_version:
            techs["React Router"]["version"] = router_version
            
    # TrustArc
    if "TrustArc" in techs and not techs["TrustArc"].get("version"):
        trustarc_version = _extract_trustarc_version(content)
        if trustarc_version:
            techs["TrustArc"]["version"] = trustarc_version
            
    # Snowplow
    if "Snowplow Analytics" in techs and not techs["Snowplow Analytics"].get("version"):
        snowplow_version = _extract_snowplow_version(content)
        if snowplow_version:
            techs["Snowplow Analytics"]["version"] = snowplow_version
    
    # Alpine.js
    if "Alpine.js" in techs and not techs["Alpine.js"].get("version"):
        alpine_version = _extract_alpine_version(content)
        if alpine_version:
            techs["Alpine.js"]["version"] = alpine_version
            
    # htmx
    if "htmx" in techs and not techs["htmx"].get("version"):
        htmx_version = _extract_htmx_version(content)
        if htmx_version:
            techs["htmx"]["version"] = htmx_version
            
    # Preact
    if "Preact" in techs and not techs["Preact"].get("version"):
        preact_version = _extract_preact_version(content)
        if preact_version:
            techs["Preact"]["version"] = preact_version
            
    # GSAP
    if "GSAP" in techs and not techs["GSAP"].get("version"):
        gsap_version = _extract_gsap_version(content)
        if gsap_version:
            techs["GSAP"]["version"] = gsap_version
            
    # Tailwind CSS
    if "Tailwind CSS" in techs and not techs["Tailwind CSS"].get("version"):
        tailwind_version = _extract_tailwind_version(content)
        if tailwind_version:
            techs["Tailwind CSS"]["version"] = tailwind_version
            
    # Storybook
    if "Storybook" in techs and not techs["Storybook"].get("version"):
        storybook_version = _extract_storybook_version(content)
        if storybook_version:
            techs["Storybook"]["version"] = storybook_version
            
    # Cypress
    if "Cypress" in techs and not techs["Cypress"].get("version"):
        cypress_version = _extract_cypress_version(content)
        if cypress_version:
            techs["Cypress"]["version"] = cypress_version


def _extract_wordpress_version(content: str) -> Optional[str]:
    """Extract WordPress version from HTML content using additional methods"""
    # Method 1: Meta generator tag
    match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([0-9\.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 2: Version in script path
    match = re.search(r'wp-includes/js/wp-emoji-release\.min\.js\?ver=([0-9\.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 3: RSS feed link
    match = re.search(r'<link\s+rel=["\']alternate["\']\s+.+?/feed/["\']?\s+.+?version=([0-9\.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 4: wp_version variable
    match = re.search(r'var\s+wp_version\s*=\s*[\'"]([0-9\.]+)[\'"]', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_jquery_version(content: str) -> Optional[str]:
    """Extract jQuery version from HTML content using additional methods"""
    # Method 1: Comment in minified code
    match = re.search(r'\/\*!\s*jQuery\s+v([0-9\.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 2: URL parameter
    match = re.search(r'jquery[.-]([0-9\.]+)\.min\.js', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 3: In jQuery object
    match = re.search(r'jQuery\.fn\.jquery\s*=\s*["\']([0-9.]+)["\']', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 4: In script source with version
    match = re.search(r'jquery/([0-9\.]+)/jquery(\.min)?\.js', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_bootstrap_version(content: str) -> Optional[str]:
    """Extract Bootstrap version from HTML content using additional methods"""
    # Method 1: Comment in minified code
    match = re.search(r'\/\*!\s*Bootstrap\s+v([0-9\.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 2: URL parameter
    match = re.search(r'bootstrap[.-]([0-9\.]+)\.min\.(?:js|css)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 3: Data attribute
    match = re.search(r'data-bootstrap-version=["\']([0-9\.]+)["\']', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 4: CDN URL
    match = re.search(r'cdn\..+?/bootstrap/([0-9\.]+)/', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_react_version(content: str) -> Optional[str]:
    """Extract React version from HTML content"""
    # Method 1: React version comment
    match = re.search(r'\/\*!\s*React\s+v([0-9\.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 2: Script source
    match = re.search(r'react@([0-9\.]+)/(?:umd|dist)/react', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 3: React version in variable
    match = re.search(r'React\.version\s*=\s*["\']([0-9.]+)["\']', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 4: React Router version
    if "React Router" in content:
        match = re.search(r'react-router@([0-9\.]+)/', content, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None

def _extract_vue_version(content: str) -> Optional[str]:
    """Extract Vue.js version from HTML content"""
    # Method 1: Vue version comment
    match = re.search(r'\/\*!\s*Vue\.js\s+v([0-9\.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 2: Script source
    match = re.search(r'vue@([0-9\.]+)/(?:dist|lib)/vue', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 3: Vue version in variable
    match = re.search(r'Vue\.version\s*=\s*["\']([0-9.]+)["\']', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_next_version(content: str) -> Optional[str]:
    """Extract Next.js version from HTML content"""
    # Method 1: Next.js data
    match = re.search(r'"nextExport":.*?"version":"([0-9\.]+)"', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 2: Script source
    match = re.search(r'next/([0-9\.]+)/(?:dist|static)', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 3: Next.js comment
    match = re.search(r'\/\*!\s*Next\.js\s+v?([0-9\.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_clarity_version(content: str) -> Optional[str]:
    """Extract Microsoft Clarity version from HTML content"""
    match = re.search(r'clarity/tag/([0-9\.]+)/', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    match = re.search(r'clarity-js/([0-9\.]+)/', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_rails_version(content: str) -> Optional[str]:
    """Extract Ruby on Rails version from HTML content"""
    # Method 1: Rails version in meta or comments
    match = re.search(r'Rails\s+([0-9][0-9.]*)', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 2: Rails version in asset path
    match = re.search(r'/rails-([0-9][0-9.]*)/rails\.js', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 3: Rails version in package
    match = re.search(r'rails@([0-9][0-9.]*)', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 4: Rails version in generator tag
    match = re.search(r'content="Ruby on Rails ([0-9][0-9.]*)"', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_ruby_version(content: str) -> Optional[str]:
    """Extract Ruby version from HTML content"""
    # Method 1: Ruby version in meta or comments
    match = re.search(r'Ruby(?:\s+version)?\s+([0-9][0-9.]*)', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 2: Ruby version in RVM settings
    match = re.search(r'rvm/rubies/ruby-([0-9][0-9.]*)', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 3: Ruby version in Gemfile
    match = re.search(r'ruby\s+[\'"]([0-9][0-9.]*)[\'"]', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_corejs_version(content: str) -> Optional[str]:
    """Extract core-js version from HTML content"""
    # Method 1: NPM/CDN URL
    match = re.search(r'core-js@([0-9.]+)/', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 2: Path version
    match = re.search(r'core-js/([0-9.]+)/', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 3: Version comment
    match = re.search(r'core-js\s+v?([0-9.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_gutenberg_version(content: str) -> Optional[str]:
    """Extract Gutenberg editor version from HTML content"""
    match = re.search(r'gutenberg/([0-9\.]+)/', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    match = re.search(r'"gutenbergVersion":"([0-9\.]+)"', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_styled_components_version(content: str) -> Optional[str]:
    """Extract styled-components version from HTML content"""
    # Method 1: NPM/CDN URL
    match = re.search(r'styled-components@([0-9\.]+)/', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 2: Version in data attribute
    match = re.search(r'data-styled-components-version=["\']([0-9\.]+)["\']', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 3: Version comment
    match = re.search(r'\/\*!\s*styled-components\s+v([0-9\.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_swiper_version(content: str) -> Optional[str]:
    """Extract Swiper version from HTML content"""
    # Method 1: NPM/CDN URL
    match = re.search(r'swiper[@/]([0-9\.]+)/', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 2: Version in data attribute
    match = re.search(r'data-swiper-version=["\']([0-9\.]+)["\']', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 3: Version comment
    match = re.search(r'\/\*!\s*Swiper\s+v([0-9\.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_react_router_version(content: str) -> Optional[str]:
    """Extract React Router version from HTML content"""
    # Method 1: NPM/CDN URL
    match = re.search(r'react-router(?:-dom)?[@/]([0-9\.]+)/', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Method 2: Version comment
    match = re.search(r'\/\*!\s*React\s+Router\s+v([0-9\.]+)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_trustarc_version(content: str) -> Optional[str]:
    """Extract TrustArc version from HTML content"""
    # Method 1: TrustArc version in script
    match = re.search(r'trustarc-version["\']?\s*[:=]\s*["\']([0-9][0-9.]*)["\']', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 2: TrustArc version comment
    match = re.search(r'TrustArc\s+Tag\s+v?([0-9][0-9.]*)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_snowplow_version(content: str) -> Optional[str]:
    """Extract Snowplow Analytics version from HTML content"""
    # Method 1: Snowplow version in script
    match = re.search(r'snowplow@([0-9][0-9.]*)', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 2: Snowplow version in config
    match = re.search(r'snowplowVersion["\']?\s*[:=]\s*["\']([0-9][0-9.]*)["\']', content, re.IGNORECASE)
    if match:
        return match.group(1)
        
    # Method 3: Snowplow in comments
    match = re.search(r'Snowplow\s+v?([0-9][0-9.]*)', content, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None

def _extract_alpine_version(content: str) -> Optional[str]:
    """Extract Alpine.js version from content."""
    version_match = re.search(r'(?:Alpine\.js|alpine\.js)[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content, re.I)
    if version_match:
        return version_match.group(1)
        
    # Check for version in script tag
    script_match = re.search(r'alpine@([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content)
    if script_match:
        return script_match.group(1)
        
    return None

def _extract_htmx_version(content: str) -> Optional[str]:
    """Extract htmx version from content."""
    version_match = re.search(r'htmx\.org\/(?:dist\/)?htmx[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content, re.I)
    if version_match:
        return version_match.group(1)
        
    # Look for version comment in HTML
    version_match = re.search(r'<!--\s*htmx\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*-->', content, re.I)
    if version_match:
        return version_match.group(1)
        
    # Check for unpkg or CDN link with version
    cdn_match = re.search(r'unpkg\.com\/htmx\.org@([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content)
    if cdn_match:
        return cdn_match.group(1)
        
    return None

def _extract_preact_version(content: str) -> Optional[str]:
    """Extract Preact version from content."""
    version_match = re.search(r'(?:Preact|preact)[^0-9]*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content, re.I)
    if version_match:
        return version_match.group(1)
        
    # Check for version in script tag
    script_match = re.search(r'preact@([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content)
    if script_match:
        return script_match.group(1)
        
    return None

def _extract_gsap_version(content: str) -> Optional[str]:
    """Extract GSAP (GreenSock Animation Platform) version from content."""
    version_match = re.search(r'(?:gsap|GreenSock)[^0-9]*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content, re.I)
    if version_match:
        return version_match.group(1)
        
    script_match = re.search(r'gsap@([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content)
    if script_match:
        return script_match.group(1)
        
    return None

def _extract_tailwind_version(content: str) -> Optional[str]:
    """Extract Tailwind CSS version from content."""
    version_match = re.search(r'tailwindcss[^0-9]*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content, re.I)
    if version_match:
        return version_match.group(1)
        
    # Check for version in class
    class_match = re.search(r'tailwind-([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content)
    if class_match:
        return class_match.group(1)
        
    return None

def _extract_storybook_version(content: str) -> Optional[str]:
    """Extract Storybook version from content."""
    version_match = re.search(r'storybook[^0-9]*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content, re.I)
    if version_match:
        return version_match.group(1)
        
    return None

def _extract_cypress_version(content: str) -> Optional[str]:
    """Extract Cypress version from content."""
    version_match = re.search(r'cypress[^0-9]*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content, re.I)
    if version_match:
        return version_match.group(1)
        
    return None


def _prepare_for_cve_detection(techs: Dict[str, Any]) -> List[Dict[str, str]]:
    """Prepare technology data for CVE detection
    
    Converts detected technologies to a format compatible with the
    CVE checker (utils.cve.check_components).
    
    Returns:
        List of dicts with 'name' and 'version' keys
    """
    components = []
    
    # Technology to package name mapping for CVE detection
    # This maps our technology names to the package names used in CVE databases
    tech_to_package = {
        "jQuery": "jquery",
        "Bootstrap": "bootstrap",
        "React": "react",
        "Vue.js": "vue",
        "Next.js": "next",
        "Angular": "angular",
        "core-js": "core-js",
        "WordPress": "wordpress",
        "Drupal": "drupal",
        "Joomla": "joomla",
        "Magento": "magento",
        "Ruby on Rails": "rails",
        "Ruby": "ruby",
        "Node.js": "node",
        "Express": "express",
        "Django": "django",
        "Flask": "flask",
        "ASP.NET": "aspnet",
        "PHP": "php",
        "Apache": "httpd",
        "nginx": "nginx",
        "Struts": "struts",
        "Log4j": "log4j",
        "Spring": "spring-core",
        "WooCommerce": "woocommerce",
        "Shopify": "shopify",
        "PrestaShop": "prestashop",
        "OpenCart": "opencart",
        "Lodash": "lodash",
        "Moment.js": "moment",
        "Axios": "axios",
        "styled-components": "styled-components",
        "Tailwind": "tailwindcss",
        "Material-UI": "material-ui",
        "Foundation": "foundation",
        "Webpack": "webpack",
        "Babel": "babel",
        "NPM": "npm",
        "Yarn": "yarn",
        "PostgreSQL": "postgresql",
        "MySQL": "mysql",
        "MongoDB": "mongodb",
        "Mongoose": "mongoose",
        "Swiper": "swiper",
        "Ember.js": "ember",
        "Svelte": "svelte",
        "Nuxt.js": "nuxt",
        "Preact": "preact",
        "React Router": "react-router",
    }
    
    # Add additional package variants for better CVE detection
    package_variants = {
        "react": ["react-dom", "react-scripts"],
        "angular": ["@angular/core", "@angular/common", "@angular/forms"],
        "vue": ["vue-router", "vuex"],
        "rails": ["actionpack", "activerecord", "activestorage", "actioncable"],
        "spring-core": ["spring-boot", "spring-framework", "spring-security"],
    }
    
    # Process detected technologies
    for tech_name, tech_data in techs.items():
        if tech_name in ("cve_vulns", "cve_details"):
            continue
            
        # Get normalized package name
        package_name = tech_to_package.get(tech_name, tech_name.lower())
        version = tech_data.get("version", "") if isinstance(tech_data, dict) else ""
        
        # Add the main component
        if version:
            components.append({"name": package_name, "version": version})
            
            # Add package variants with the same version
            if package_name in package_variants:
                for variant in package_variants[package_name]:
                    components.append({"name": variant, "version": version})
    
    return components


def detect_technologies(url: str, use_cache: bool = True, use_active_scan: bool = False, filter_fps: bool = True) -> Optional[Dict[str, Any]]:
    """Detect technologies used on a website using browser-free methods
    
    Args:
        url: The URL to analyze
        use_cache: Whether to use cached results
        use_active_scan: Whether to use active scanning techniques
        filter_fps: Whether to filter out likely false positives
        
    Returns:
        Dict of detected technologies with their details or None if failed
    """
    try:
        # Check for cached results
        import os
        import json
        import hashlib
        
        # Create a unique hash for this URL to use as cache key
        url_hash = hashlib.md5(url.encode()).hexdigest()
        
        # Set up cache directory
        cache_dir = os.path.join("db")
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
        cache_file = os.path.join(cache_dir, "tech_cache.json")
        
        # Try to load from cache first
        cache = {}
        if use_cache and os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    cache = json.load(f)
                    
                if url_hash in cache:
                    logging.info(f"Using cached tech detection for {url}")
                    return cache[url_hash]
            except Exception as e:
                logging.warning(f"Failed to load tech cache: {e}")
                
        logging.info(f"Detecting technologies for {url}")
        
        # Fetch the webpage content
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.5, 
                       status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        from utils.user_agent_manager import get_realistic_headers
        headers = get_realistic_headers(include_scanner_header=True)
        
        response = session.get(url, headers=headers, timeout=10, verify=False)
        response.raise_for_status()
        
        # Extract headers and HTML content
        page_headers = dict(response.headers)
        html_content = response.text
        
        # Use the new tiered detection approach
        detected_techs = _perform_tiered_detection(page_headers, html_content)
        
        # If active scanning is enabled and available, use it
        if use_active_scan and ACTIVE_SCAN_AVAILABLE:
            logging.info(f"Performing active scan on {url}")
            try:
                active_techs = perform_active_scan(url, timeout=10)
                
                # Merge active scan results with passive detection results
                if active_techs:
                    for tech_name, tech_info in active_techs.items():
                        if tech_name not in detected_techs:
                            detected_techs[tech_name] = tech_info
                        elif not detected_techs[tech_name].get("version") and tech_info.get("version"):
                            # Keep version from active scan if passive didn't find one
                            detected_techs[tech_name]["version"] = tech_info["version"]
                            
                    logging.info(f"Active scan found {len(active_techs)} technologies")
            except Exception as e:
                logging.warning(f"Error during active scan: {e}")
        
        # Apply false positive filtering if enabled and available
        if filter_fps and FALSE_POSITIVE_FILTER_AVAILABLE:
            original_count = len({k: v for k, v in detected_techs.items() if k not in ('cve_vulns', 'cve_details')})
            detected_techs = filter_false_positives(detected_techs)
            filtered_count = len({k: v for k, v in detected_techs.items() if k not in ('cve_vulns', 'cve_details')})
            
            if original_count > filtered_count:
                logging.info(f"Removed {original_count - filtered_count} likely false positives")
        

        
        # Save to cache
        cache[url_hash] = detected_techs
        try:
            with open(cache_file, 'w') as f:
                json.dump(cache, f)
        except Exception as e:
            logging.warning(f"Error saving tech cache: {e}")
        
        tech_count = sum(1 for k in detected_techs if k not in ('cve_vulns', 'cve_details'))
        logging.info(f"Detected {tech_count} technologies for {url}")
        return detected_techs
        
    except requests.RequestException as e:
        logging.error(f"Error fetching URL {url}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error detecting technologies: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return None


def _perform_tiered_detection(page_headers: Dict[str, str], html_content: str) -> Dict[str, Any]:
    """
    Perform technology detection using a tiered approach for better performance:
    
    Tier 1: Headers-only detection (very fast)
    Tier 2: Quick HTML pattern matching (fast)
    Tier 3: Complex HTML pattern matching and DOM structure analysis (slower)
    
    Args:
        page_headers: Dict of HTTP response headers
        html_content: HTML content of the page
        
    Returns:
        Dict of detected technologies with their details
    """
    detected_techs = {}
    
    # Tier 1: Headers-only detection
    _detect_from_headers(page_headers, detected_techs)
    
    # Skip HTML processing if there's no content
    if not html_content:
        return detected_techs
    
    # Tier 2: Quick HTML pattern matching (simple regex patterns)
    _detect_from_quick_patterns(html_content, detected_techs)
    
    # Tier 3: Complex HTML pattern matching and DOM analysis
    _detect_from_complex_patterns(html_content, detected_techs)
    _enhance_with_dom_analysis(html_content, detected_techs)
    
    # Final step: Enhance version detection for all detected technologies
    _enhance_version_detection(detected_techs, html_content)
    
    return detected_techs

def _detect_from_headers(page_headers: Dict[str, str], detected_techs: Dict[str, Any]) -> None:
    """
    Detect technologies from HTTP headers (Tier 1 - fastest)
    
    Args:
        page_headers: Dict of HTTP response headers
        detected_techs: Dict to store detected technologies (modified in-place)
    """
    for tech_name, patterns in TECH_PATTERNS.items():
        # Skip if already detected
        if tech_name in detected_techs:
            continue
            
        # Check headers
        for header_pattern in patterns["headers"]:
            # Skip if no header patterns
            if not header_pattern:
                continue
                
            # Handle string pattern or tuple pattern
            if isinstance(header_pattern, str):
                header_name = header_pattern
                regex_pattern = None
                extractor = None
            elif isinstance(header_pattern, tuple) and len(header_pattern) >= 2:
                header_name = header_pattern[0]
                regex_pattern = header_pattern[1]
                extractor = header_pattern[2] if len(header_pattern) > 2 else None
            else:
                continue  # Skip invalid patterns
            
            # Find matching header
            header_value = None
            if isinstance(header_name, str):
                # String header name - direct match
                for k, v in page_headers.items():
                    if k.lower() == header_name.lower():
                        header_value = v
                        break
            elif isinstance(header_name, re.Pattern):
                # Regex header pattern - search in keys
                for k, v in page_headers.items():
                    if header_name.search(k):
                        header_value = v
                        break
            
            # If we found a matching header
            if header_value:
                version = ""
                # Check header value against pattern if one was provided
                if regex_pattern:
                    if isinstance(regex_pattern, str):
                        match = re.search(regex_pattern, header_value, re.IGNORECASE)
                        if match and match.groups():
                            version = match.group(1)
                    elif isinstance(regex_pattern, re.Pattern):
                        match = regex_pattern.search(header_value)
                        if match and match.groups():
                            version = match.group(1)
                    # Use custom extractor if provided
                    if extractor and callable(extractor) and match:
                        version_match = extractor(match, header_value)
                        if version_match:
                            if hasattr(version_match, 'group'):
                                version = version_match.group(1)
                            else:
                                version = version_match
                
                detected_techs[tech_name] = {
                    "version": version, 
                    "confidence": "high", 
                    "source": "header"
                }
                break

def _detect_from_quick_patterns(html_content: str, detected_techs: Dict[str, Any]) -> None:
    """
    Detect technologies from quick HTML patterns (Tier 2 - fast)
    These are simple regex patterns that don't require complex processing
    
    Args:
        html_content: HTML content of the page
        detected_techs: Dict to store detected technologies (modified in-place)
    """
    # Define quick patterns - these are fast to check
    quick_checks = {
        # Meta tags
        "WordPress": r'<meta[^>]+content=["\'](WordPress|WP)["\']',
        "Bootstrap": r'bootstrap(?:\.min)?\.css',
        "jQuery": r'jquery(?:\.min)?\.js',
        "React": r'react(?:\.production|\.development|\.min)?\.js',
        "Vue.js": r'vue(?:\.min)?\.js',
        "Angular": r'angular(?:\.min)?\.js',
        "Tailwind CSS": r'tailwindcss|tailwind\.css',
        "Google Analytics": r'google-analytics\.com|gtag\s*\(|googletagmanager',
        "Google Tag Manager": r'googletagmanager\.com|gtm\.js',
        "Google Fonts": r'fonts\.googleapis\.com',
        "Font Awesome": r'font-awesome(?:\.min)?\.css',
        "Cloudflare": r'cloudflare\.com|cdnjs\.cloudflare\.com',
        "Amazon S3": r'amazonaws\.com\/s3',
        "CloudFront": r'cloudfront\.net',
        "Shopify": r'cdn\.shopify\.com',
    }
    
    # Run quick checks first
    for tech_name, pattern in quick_checks.items():
        # Skip if already detected
        if tech_name in detected_techs:
            continue
            
        if re.search(pattern, html_content, re.IGNORECASE):
            detected_techs[tech_name] = {
                "version": "",
                "confidence": "medium", 
                "source": "quick_pattern"
            }

def _detect_from_complex_patterns(html_content: str, detected_techs: Dict[str, Any]) -> None:
    """
    Detect technologies from complex HTML patterns (Tier 3 - slower)
    These are more complex patterns that require more processing
    
    Args:
        html_content: HTML content of the page
        detected_techs: Dict to store detected technologies (modified in-place)
    """
    for tech_name, patterns in TECH_PATTERNS.items():
        # Skip if already detected or if no HTML patterns
        if tech_name in detected_techs or not patterns["html"]:
            continue
            
        for html_pattern in patterns["html"]:
            # Handle string pattern or tuple pattern
            if isinstance(html_pattern, str):
                regex_pattern = html_pattern
                extractor = None
            elif isinstance(html_pattern, tuple) and len(html_pattern) >= 2:
                regex_pattern = html_pattern[0]
                extractor = html_pattern[1]
            else:
                continue  # Skip invalid patterns
            
            version = ""
            match = None
            if isinstance(regex_pattern, str):
                match = re.search(regex_pattern, html_content, re.IGNORECASE | re.DOTALL)
                if match and match.groups():
                    version = match.group(1)
            elif isinstance(regex_pattern, re.Pattern):
                match = regex_pattern.search(html_content)
                if match and match.groups():
                    version = match.group(1)
            
            # Use custom extractor if provided
            if extractor and callable(extractor) and match:
                version_match = extractor(match, html_content)
                if version_match:
                    if hasattr(version_match, 'group'):
                        version = version_match.group(1)
                    else:
                        version = version_match
            
            if match:
                detected_techs[tech_name] = {
                    "version": version, 
                    "confidence": "medium", 
                    "source": "complex_pattern"
                }
                break

def _enhance_with_dom_analysis(html_content: str, detected_techs: Dict[str, Any]) -> None:
    """
    Enhance technology detection with DOM structure analysis (Tier 3 - slower)
    
    Args:
        html_content: HTML content of the page
        detected_techs: Dict to store detected technologies (modified in-place)
    """
    # Get technologies detected through DOM analysis
    dom_techs = _analyze_dom_structure(html_content)
    
    # Merge with existing detected technologies
    for tech_name, tech_info in dom_techs.items():
        if tech_name not in detected_techs:
            detected_techs[tech_name] = tech_info
        else:
            # Keep version info if already detected
            detected_techs[tech_name].update({
                k: v for k, v in tech_info.items() 
                if k != "version" or "version" not in detected_techs[tech_name]
            })


def _analyze_dom_structure(content: str) -> Dict[str, Any]:
    """
    Analyze DOM structure for common patterns that indicate specific technologies.
    This is a more advanced detection method than simple regex matching.
    
    Returns:
        Dictionary of detected technologies
    """
    techs = {}
    
    # Extract all element attributes for analysis
    all_attributes = {}
    attr_pattern = re.compile(r'<([a-z0-9]+)[^>]*?([a-z0-9\-]+)=["\'](.*?)["\']', re.I)
    for match in attr_pattern.finditer(content):
        elem_type = match.group(1).lower()
        attr_name = match.group(2).lower()
        attr_value = match.group(3)
        
        if elem_type not in all_attributes:
            all_attributes[elem_type] = {}
        
        if attr_name not in all_attributes[elem_type]:
            all_attributes[elem_type][attr_name] = []
            
        all_attributes[elem_type][attr_name].append(attr_value)
    
    # React/JSX detection based on data attributes structure
    react_indicators = 0
    if 'div' in all_attributes:
        for attr in all_attributes['div']:
            if attr.startswith('data-reactid') or attr.startswith('data-react'):
                react_indicators += 3
            if 'data-reactroot' in all_attributes['div']:
                react_indicators += 5
            if any('__reactEventHandlers' in val for vals in all_attributes['div'].values() for val in vals):
                react_indicators += 5
                
    # Also check for JSX class name pattern
    jsx_class_pattern = re.compile(r'className=["\'](.*?)["\']', re.I)
    if jsx_class_pattern.search(content):
        react_indicators += 3
        
    if react_indicators >= 3 and "React" not in techs:
        techs["React"] = {"confidence": min(react_indicators, 10) / 10}
        
    # Angular detection based on attributes
    angular_indicators = 0
    ng_attrs = ['ng-app', 'ng-model', 'ng-controller', 'ng-repeat', 'ng-if', 'ng-class', 'ng-click']
    for elem_type, attrs in all_attributes.items():
        for attr in ng_attrs:
            if attr in attrs:
                angular_indicators += 2
                
    # Angular directives
    dir_pattern = re.compile(r'<([a-z0-9\-]+)(?:-[a-z0-9\-]+)+', re.I)
    if dir_pattern.search(content):
        angular_indicators += 1
        
    if angular_indicators >= 2 and "Angular" not in techs:
        techs["Angular"] = {"confidence": min(angular_indicators, 10) / 10}
        
    # Svelte detection
    svelte_indicators = 0
    if re.search(r'__SVELTE', content):
        svelte_indicators += 5
        
    if svelte_indicators >= 2 and "Svelte" not in techs:
        techs["Svelte"] = {"confidence": min(svelte_indicators, 10) / 10}
    
    # WordPress content structure
    wp_indicators = 0
    if re.search(r'<div[^>]+wp-(?:content|block|embed)', content):
        wp_indicators += 3
        
    if re.search(r'wp-(?:includes|content|admin|embed|json)', content):
        wp_indicators += 2
        
    if re.search(r'/wp-content/themes/', content):
        wp_indicators += 5
        
    if re.search(r'/wp-content/plugins/', content):
        wp_indicators += 3
        
    if wp_indicators >= 3 and "WordPress" not in techs:
        techs["WordPress"] = {"confidence": min(wp_indicators, 10) / 10}
    
    # Shopify store detection
    shopify_indicators = 0
    if re.search(r'cdn\.shopify\.com', content):
        shopify_indicators += 3
        
    if re.search(r'shopify\.com/s/', content):
        shopify_indicators += 5
        
    if re.search(r'Shopify\.theme', content):
        shopify_indicators += 5
        
    if shopify_indicators >= 3 and "Shopify" not in techs:
        techs["Shopify"] = {"confidence": min(shopify_indicators, 10) / 10}
    
    # Analytics and marketing tools based on dom structure
    tools = {
        "Google Tag Manager": [r'googletagmanager\.com', r'gtm\.js', r'GTM-[A-Z0-9]+'],
        "Google Analytics": [r'google-analytics\.com', r'analytics\.js', r'gtag\('],
        "Google Ads": [r'googleadservices\.com', r'conversion_async\.js'],
        "Facebook Pixel": [r'connect\.facebook\.net', r'fbq\('],
        "LinkedIn Insight": [r'linkedin\.com/analytics', r'_linkedin_data_partner_id'],
        "HubSpot": [r'js\.hs-scripts\.com', r'hs-script-loader'],
        "Intercom": [r'intercom\.io', r'intercomSettings'],
        "Optimizely": [r'optimizely\.com', r'optimizely\.push'],
        "Hotjar": [r'static\.hotjar\.com', r'hjSetting'],
    }
    
    for tool_name, patterns in tools.items():
        indicators = 0
        for pattern in patterns:
            if re.search(pattern, content, re.I):
                indicators += 3
                
        if indicators >= 3 and tool_name not in techs:
            techs[tool_name] = {"confidence": min(indicators, 10) / 10}
    
    return techs


if __name__ == "__main__":
    # Test the module
    import sys
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = "https://www.example.com"
    
    print(f"Detecting technologies for {url}...")
    techs = detect_technologies(url)
    
    if techs:
        print(f"Found {len(techs)} technologies:")
        for name, info in techs.items():
            version = info.get("version", "unknown version")
            print(f"- {name}: {version}")
    else:
        print("No technologies detected or detection failed.") 