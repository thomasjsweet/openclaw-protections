# DNS Filtering Blocklist

Block the following domains to prevent unauthorized AI agent tools from functioning.

## Primary Tool Domains

```
# OpenClaw
openclaw.ai
*.openclaw.ai
docs.openclaw.ai

# Clawdbot
clawdhub.com
*.clawdhub.com
clawd.bot
*.clawd.bot

# Moltbot
molt.bot
*.molt.bot
moltbot.dev
*.moltbot.dev

# Related Services
deepwiki.com
soul.md
```

## API Endpoints (Selective)

These are used by AI agents but may have legitimate uses. Block if you don't have authorized AI tools in your environment:

```
# ElevenLabs (Text-to-Speech)
api.elevenlabs.io
*.elevenlabs.io

# OpenRouter (Multi-model proxy)
openrouter.ai
*.openrouter.ai

# Firecrawl (Web scraping)
api.firecrawl.dev
*.firecrawl.dev

# Brave Search API
api.brave.com
```

## Keep ALLOWED (If Using Authorized AI Tools)

```
# Anthropic API - Keep allowed if using Claude officially
api.anthropic.com

# OpenAI API - Keep allowed if using GPT officially  
api.openai.com
```

## Optional Block (Consumer AI Access)

Block if you want to prevent consumer Claude/ChatGPT web access:

```
claude.ai
chat.openai.com
chatgpt.com
```

## Implementation Notes

### DNSFilter
1. Navigate to **Policies > Custom Block Lists**
2. Add domains above
3. Apply to appropriate policies

### Cisco Umbrella
1. Navigate to **Policies > Destination Lists**
2. Create new block list
3. Add domains
4. Apply to policies

### Microsoft Defender for Endpoint
1. Navigate to **Settings > Endpoints > Indicators**
2. Add URL/Domain indicators
3. Set action to Block

## Testing

After implementing blocks, verify by attempting to resolve blocked domains:

```powershell
Resolve-DnsName openclaw.ai
Resolve-DnsName clawdhub.com
```

Blocked domains should return NXDOMAIN or your DNS filter's block page.
