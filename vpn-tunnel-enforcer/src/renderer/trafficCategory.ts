export type TrafficBadgeVariant = 'neutral' | 'success' | 'warning' | 'danger' | 'accent'

export interface TrafficCategory {
  label: string
  variant: TrafficBadgeVariant
  confidence: 'high' | 'medium' | 'low'
}

type CategoryRule = TrafficCategory & {
  domains?: string[]
  suffixes?: string[]
  keywords?: RegExp[]
}

const COMMON_SECOND_LEVEL_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'gov.uk',
  'ac.uk',
  'com.au',
  'net.au',
  'org.au',
  'com.br',
  'com.cn',
  'com.hk',
  'co.jp',
  'ne.jp',
  'or.jp',
  'co.kr',
  'com.mx',
  'com.tr',
  'com.ua',
  'com.ru',
  'com.sg',
  'co.nz',
  'co.za'
])

const TRACKING_RULES: CategoryRule[] = [
  {
    label: 'Угроза / Фишинг',
    variant: 'danger',
    confidence: 'medium',
    keywords: [
      /(?:^|[.-])(malware|phishing|scam|cryptojack|coinhive|fake-update|urlhaus|badware)(?:[.-]|$)/,
      /(?:^|[.-])(stealer|botnet|ransom|trojan|exploit-kit)(?:[.-]|$)/
    ]
  },
  {
    label: 'Реклама / RTB',
    variant: 'danger',
    confidence: 'high',
    domains: [
      'doubleclick.net',
      'googlesyndication.com',
      'googleadservices.com',
      'adsystem.com',
      'adsrvr.org',
      'adnxs.com',
      'openx.net',
      'pubmatic.com',
      'criteo.com',
      'taboola.com',
      'outbrain.com',
      'rubiconproject.com',
      'yieldmo.com',
      'bidr.io',
      '360yield.com'
    ],
    keywords: [
      /(?:^|[.-])(adservice|adserver|adsystem|adtech|adform|adroll|adzerk|adition|adcolony)(?:[.-]|$)/,
      /(?:^|[.-])(rtb|bidder|prebid|programmatic|impression|creative|servedbyad)(?:[.-]|$)/
    ]
  },
  {
    label: 'Аналитика / Трекинг',
    variant: 'danger',
    confidence: 'high',
    domains: [
      'google-analytics.com',
      'googletagmanager.com',
      'cloudflareinsights.com',
      'scorecardresearch.com',
      'hotjar.com',
      'segment.io',
      'mixpanel.com',
      'amplitude.com',
      'appsflyer.com',
      'adjust.com',
      'branch.io',
      'flurry.com',
      'fullstory.com',
      'newrelic.com',
      'sentry.io'
    ],
    keywords: [
      /(?:^|[.-])(analytics|metrics|tracking|tracker|beacon|pixel|tagmanager|telemetry)(?:[.-]|$)/,
      /(?:^|[.-])(app-measurement|audience|crashlytics|session-replay|heatmap)(?:[.-]|$)/
    ]
  },
  {
    label: 'Телеметрия',
    variant: 'warning',
    confidence: 'high',
    domains: [
      'events.data.microsoft.com',
      'watson.events.data.microsoft.com',
      'vortex.data.microsoft.com',
      'settings-win.data.microsoft.com',
      'firebaselogging-pa.googleapis.com',
      'firebase-settings.crashlytics.com',
      'appcenter.ms'
    ],
    keywords: [
      /(?:^|[.-])(telemetry|diagnostics|crash|crashes|events\.data|logging|logs|log-upload)(?:[.-]|$)/,
      /(?:^|[.-])(insights|telemetrydeck|bugsnag|hockeyapp)(?:[.-]|$)/
    ]
  }
]

const SERVICE_RULES: CategoryRule[] = [
  {
    label: 'Мессенджеры',
    variant: 'accent',
    confidence: 'high',
    domains: [
      'telegram.org',
      't.me',
      'whatsapp.com',
      'whatsapp.net',
      'discord.com',
      'discordapp.com',
      'slack.com',
      'teams.microsoft.com',
      'skype.com',
      'viber.com',
      'signal.org'
    ]
  },
  {
    label: 'Соцсети',
    variant: 'accent',
    confidence: 'high',
    domains: [
      'facebook.com',
      'facebook.net',
      'instagram.com',
      'twitter.com',
      'x.com',
      'twimg.com',
      'tiktok.com',
      'vk.com',
      'linkedin.com',
      'snapchat.com',
      'pinterest.com',
      'reddit.com'
    ]
  },
  {
    label: 'Медиа / Стриминг',
    variant: 'accent',
    confidence: 'high',
    domains: [
      'youtube.com',
      'youtu.be',
      'googlevideo.com',
      'ytimg.com',
      'netflix.com',
      'nflxvideo.net',
      'spotify.com',
      'scdn.co',
      'twitch.tv',
      'ttvnw.net',
      'vimeo.com',
      'hulu.com',
      'disneyplus.com',
      'primevideo.com',
      'applemusic.com',
      'music.apple.com',
      'soundcloud.com'
    ],
    keywords: [/(?:^|[.-])(stream|video|vod|hls|dash|media|podcast)(?:[.-]|$)/]
  },
  {
    label: 'Разработка / AI',
    variant: 'success',
    confidence: 'high',
    domains: [
      'github.com',
      'githubusercontent.com',
      'githubassets.com',
      'gitlab.com',
      'bitbucket.org',
      'npmjs.com',
      'npmjs.org',
      'pypi.org',
      'pythonhosted.org',
      'docker.com',
      'docker.io',
      'ghcr.io',
      'huggingface.co',
      'openai.com',
      'anthropic.com',
      'claude.ai',
      'cursor.sh',
      'visualstudio.com',
      'vscode.dev'
    ]
  },
  {
    label: 'Облако / CDN',
    variant: 'neutral',
    confidence: 'high',
    domains: [
      'cloudflare.com',
      'cloudflare.net',
      'cloudfront.net',
      'amazonaws.com',
      'azureedge.net',
      'trafficmanager.net',
      'akamaihd.net',
      'akamaiedge.net',
      'akadns.net',
      'fastly.net',
      'fastlylb.net',
      'edgecastcdn.net',
      'gstatic.com',
      'googleapis.com',
      '1e100.net',
      'gvt1.com',
      'gvt2.com',
      'jsdelivr.net',
      'unpkg.com',
      'cloudinary.com'
    ],
    keywords: [/(?:^|[.-])(cdn|static|assets|edge|cache|imgix|images|media-cdn)(?:[.-]|$)/]
  },
  {
    label: 'Системные обновления',
    variant: 'neutral',
    confidence: 'high',
    domains: [
      'windowsupdate.com',
      'update.microsoft.com',
      'delivery.mp.microsoft.com',
      'download.windowsupdate.com',
      'apple.com',
      'icloud.com',
      'mzstatic.com',
      'gvt1.com',
      'gvt2.com',
      'android.clients.google.com'
    ],
    keywords: [/(?:^|[.-])(update|updates|download|ota|softwareupdate)(?:[.-]|$)/]
  },
  {
    label: 'Почта',
    variant: 'warning',
    confidence: 'high',
    domains: [
      'gmail.com',
      'googlemail.com',
      'outlook.com',
      'office365.com',
      'protection.outlook.com',
      'mail.ru',
      'yandex.ru',
      'yandex.net',
      'proton.me',
      'protonmail.com',
      'icloud.com'
    ],
    keywords: [/(?:^|[.-])(mail|smtp|imap|pop3|mx|webmail)(?:[.-]|$)/]
  },
  {
    label: 'Платежи',
    variant: 'warning',
    confidence: 'high',
    domains: [
      'stripe.com',
      'paypal.com',
      'paypalobjects.com',
      'checkout.com',
      'adyen.com',
      'cloudpayments.ru',
      'yookassa.ru',
      'robokassa.ru',
      'tinkoff.ru'
    ]
  },
  {
    label: 'Авторизация / SSO',
    variant: 'neutral',
    confidence: 'medium',
    domains: [
      'login.microsoftonline.com',
      'accounts.google.com',
      'auth0.com',
      'okta.com',
      'onelogin.com',
      'appleid.apple.com'
    ],
    keywords: [/(?:^|[.-])(login|auth|oauth|sso|identity|idp|signin|account)(?:[.-]|$)/]
  },
  {
    label: 'Маркетплейсы',
    variant: 'accent',
    confidence: 'medium',
    domains: [
      'amazon.com',
      'amazon.de',
      'amazon.co.uk',
      'aliexpress.com',
      'ebay.com',
      'ozon.ru',
      'wildberries.ru',
      'market.yandex.ru'
    ],
    keywords: [/(?:^|[.-])(shop|store|market|checkout|cart)(?:[.-]|$)/]
  }
]

const ALL_RULES = [...TRACKING_RULES, ...SERVICE_RULES]

export function normalizeTrafficDomain(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^\*\./, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .replace(/\.$/, '')
}

export function registrableDomain(domain: string): string {
  const clean = normalizeTrafficDomain(domain)
  const parts = clean.split('.').filter(Boolean)
  if (parts.length <= 2) return clean
  const lastTwo = parts.slice(-2).join('.')
  if (COMMON_SECOND_LEVEL_SUFFIXES.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.')
  }
  return lastTwo
}

function matchesDomain(domain: string, site: string, candidate: string): boolean {
  return site === candidate || domain === candidate || domain.endsWith(`.${candidate}`)
}

function matchesRule(domain: string, site: string, rule: CategoryRule): boolean {
  if (rule.domains?.some(candidate => matchesDomain(domain, site, candidate))) return true
  if (rule.suffixes?.some(suffix => domain.endsWith(suffix))) return true
  if (rule.keywords?.some(pattern => pattern.test(domain))) return true
  return false
}

export function categorizeTrafficDomain(domain: string): TrafficCategory | null {
  const normalized = normalizeTrafficDomain(domain)
  if (!normalized || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(normalized)) return null

  const site = registrableDomain(normalized)
  for (const rule of ALL_RULES) {
    if (matchesRule(normalized, site, rule)) {
      return {
        label: rule.label,
        variant: rule.variant,
        confidence: rule.confidence
      }
    }
  }

  return null
}
