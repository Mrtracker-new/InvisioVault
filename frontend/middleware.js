// Vercel Edge Middleware: Intercepts social crawlers and routes them to prerendered metadata snapshots

export const config = {
  matcher: ['/steganography', '/polyglot', '/qr-code', '/docs', '/faq'],
}

const SOCIAL_BOT_REGEX = /bot|crawler|spider|facebookexternalhit|twitterbot|linkedinbot|discordbot|slackbot|telegrambot|whatsapp|bingbot|googlebot/i

export default function middleware(request) {
  const userAgent = request.headers.get('user-agent') || ''
  const isSocialBot = SOCIAL_BOT_REGEX.test(userAgent)
  const url = new URL(request.url)
  const pathname = url.pathname.replace(/\/$/, '') // normalize trailing slash

  if (isSocialBot) {
    // Rewrite social bot requests to the static pre-rendered snapshot with embedded OG tags
    const targetPath = `${pathname}/index.html`
    return new Response(null, {
      headers: {
        'x-middleware-rewrite': targetPath,
        'x-social-bot-detected': 'true',
      },
    })
  }

  // Normal human visitors proceed to standard Vite SPA client hydration
}
