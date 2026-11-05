# Demo app

## Tool used

None: PawHaven was written by hand on 2026-11-03, in the style an AI app builder like Lovable or Bolt often produces (Vite, React, Supabase, edge functions).
No public app exists that is vulnerable on purpose for this stack, and real repos with these mistakes belong to people who never agreed to be a demo.
So the video and the examples must not say Lovable built it.

## Repo URL

- Vulnerable: https://github.com/Bsahoo99/pawhaven (commit ada5674), analysis `zUgZGi3hZnDK`.
  The first analysis, `Yfn1aENDRkh-` at commit 2849802, predates the fix-advice check and told staff to keep the browser admin client.
- Fixed: https://github.com/Bsahoo99/pawhaven-fixed (commit 7deb704), analysis `QQiLB8ZxBT5_`.

Heist only analyses a repo's latest commit, so the two versions live in two repos and the landing page offers both as example chips.
Neither app has ever been deployed or held real data.

## Prompts used

None, since no app builder was used.

## Mistakes added by hand

Every mistake is on purpose, and each is a common one in public Lovable and Bolt repos (see `docs/template-stats.md`).

1. `adoption_requests` is readable by any signed-in user, so the demo has a proved critical with personal columns (name, email, phone, home address).
2. `messages` never enables row level security, so the demo has a proved critical readable with only the anon key.
3. `src/lib/admin.ts` builds a service role client for the shelter dashboard, so the demo shows an admin key in browser code.
4. The `id-documents` bucket is public with only an upload policy, so anyone with a link can open a photo ID.
   Heist does not report this yet: the storage check skips any bucket that has a policy.
5. `send-email` and `update-request` never check the caller, so the demo shows open edge functions.
6. `ai-describe` calls OpenAI with no sign-in check, so the demo shows paid API credits anyone can spend.

The fixed repo closes each one; its README lists how.

## Live results (production, 2026-11-04)

- Vulnerable: 8 findings, 3 critical (2 proved on Modal with Test Alice rows, 1 confirmed), 3 high, 1 medium possible, 1 low possible.
- Fixed: 1 finding, the public pet list (low, possible, public on purpose), and the badge shows 7/7 locks held.
