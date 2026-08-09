# StockyShift — Video Script v3 (Re-record for App Store review, ~4:00)

Changes from v2:
- Scene 0 (Install/onboarding) restored — the review guideline asks to show the
  merchant flow; v2 cut it for convenience.
- Total runtime target 3:45–4:10 (guideline: 3–8 min; v2 was 2:16, too short).
- Scene 5 now opens the downloaded CSV on screen (visual proof + seconds).
- RECORDING QUALITY MUST BE "High" — v1/v2 were captured at "Efficient"
  (668 kbps, ~13fps) which is why the footage looked soft. Fix below.

**Format:** 1080p screen recording, portion-of-screen, narration at normal volume
**Title on upload:** StockyShift — Low Stock Alerts & Purchase Orders for Shopify
**Visibility:** Unlisted (not public)

---

## Recording setup — DO THIS FIRST (this is what went wrong last time)

1. `Cmd+Shift+5` → **Options** → **Quality: High** (Efficient is the default and
   produces the soft 668 kbps footage. High gives 5–20 Mbps.)
2. Record **portion of screen** — the browser/admin window area, not the full screen
3. Mute notifications, close other tabs, hide the dock
4. Mouse: **slow and deliberate** — 1–2 second pause after every click, then move
5. Hard-refresh the app once before take B so the latest build is live

Two takes, assembled afterwards (you will NOT see a cut between them in the final):

---

## Take A — Scene 0: Install (0:00–0:45)

**Setup:** Install StockyShift on a dev store that does NOT have it installed
yet (create a fresh dev store in Partner Dashboard if needed — seed nothing).

**Screen:** Open the install URL in a browser logged into the store admin:
`https://stockyshift.onrender.com/auth?shop=STORE.myshopify.com`
→ Shopify's install confirmation screen ("StockyShift is requesting access…")
→ click **Install** → app opens in the admin.

**Narration:**
> "Here's what getting started looks like. One click to install — no credit card,
> no setup wizard, no configuration. The trial starts the moment you're in, and
> StockyShift syncs your products automatically — so the moment you open it,
> it already knows what you sell."

**Action:** Let the install confirmation screen sit 2 seconds before clicking.
After the app opens, pause 3 seconds, then STOP recording.

**Off-camera between takes (not recorded):**
In the app: Products tab → create Ceramic Mug (stock 2), Linen T-Shirt (4),
Canvas Tote (15) → set reorder points 5 / 5 / 10 → Vendors tab → add
Sunrise Ceramics (contact@sunriseceramics.com) → assign to Mug + T-Shirt.

---

## Take B — Scenes 1–7 (~3:00)

## Scene 1 — The problem (0:45–1:20)

**Screen:** App opens on the Low Stock view — Ceramic Mug shows "2" with warning
badge, Linen T-Shirt shows "4". No clicks needed.

**Narration:**
> "Open StockyShift from your Shopify admin, and here's the first thing you see —
> everything you're about to run out of. Ceramic Mug: two left, reorder point
> five. Linen T-Shirt: four left, reorder point five. Both flagged before a
> customer ever hits an out-of-stock page. Canvas Tote's at fifteen — no alert.
> StockyShift only nags you when it matters."

**Don't:** click around. Let the badges show 2–3 seconds.

---

## Scene 2 — Reorder points (1:20–1:55)

**Screen:** Products tab → click Edit on Canvas Tote → reorder point 10 →
change to 20 → Save → **badge flips green → red live on screen** (no refresh).

**Narration:**
> "Each product has its own reorder point — your minimum healthy stock. The
> Tote's at fifteen with a reorder point of ten — healthy, no alert. But say you
> want a bigger buffer. Set it to twenty, save — and watch, StockyShift flags
> it instantly. Set it once, and it watches from then on — daily automatic sync
> means your numbers are always current."

**Action:** Pause 2 seconds after the badge flips so viewers see the reaction.

---

## Scene 3 — Vendors (1:55–2:20)

**Screen:** Vendors tab → show the Sunrise Ceramics row (already created).

**Narration:**
> "Add each supplier once — name and email — and they're stored and reused on
> every purchase order. No more hunting through old emails for who you bought
> your mugs from."

**Action:** Hover the row slowly; no clicks needed.

---

## Scene 4 — One-click PO (2:20–3:00)

**Screen:** Low Stock tab → click "Order" on Ceramic Mug → PO modal shows
quantity 3 pre-filled, vendor Sunrise Ceramics → click "Create Purchase Order".

**Narration:**
> "Now the part that saves you real time. One click on Order turns low stock
> into a purchase order. The quantity is already calculated — the deficit
> between what you have and what you need — and the supplier's already attached.
> No spreadsheets, no manual math, no retyping SKUs. Just create, and your PO
> is done."

**Action:** Let the pre-filled quantity sit on screen 2 seconds before creating.

---

## Scene 5 — The deliverable (3:00–3:35)

**Screen:** Purchase Orders tab → open the PO → click "Export CSV" → then OPEN
the downloaded CSV in Numbers/Excel so the file is visible on screen. Dashboard
stays intact. (The Send button is visible in the PO row — do NOT click it on
camera; narration only.)

**Narration:**
> "Every purchase order exports as a clean CSV file — keep it for your records,
> or open it in the tools you already use. And when your supplier needs something
> more official, Send emails the PO straight to them with a ready-to-print PDF
> attached."

**Action:** 2 seconds on the open CSV file before switching back.

---

## Scene 6 — Pricing (3:35–3:55)

**Screen:** Settings tab — subscription card (Starter, $29.00/month, status).

**Narration:**
> "Pricing is simple — one plan, twenty-nine dollars a month, with a seven-day
> free trial. No tier gymnastics, no per-product fees. Manage or cancel right
> through Shopify, any time."

**Check:** no diagnostic text on screen (removed — clean build).

---

## Scene 7 — Close (3:55–4:10)

**Screen:** Back to Low Stock view.

**Narration:**
> "StockyShift. Stop running out of stock — and stop guessing what to reorder.
> Install it free from the Shopify App Store — and start your seven-day trial
> today."

---

## After recording

1. Save both takes into `/Users/yashoraj/stockyshift/recordings/` and tell me the filenames
2. I will: find scene boundaries, overlay narration per scene, assemble to
   1600-wide master → you upload as new YouTube video (unlisted, same title)
3. Swap the new URL into the listing's Screencast field

## Upload rules

- Unlisted YouTube video (not public)
- Title: StockyShift — Low Stock Alerts & Purchase Orders for Shopify
- Calm narration at normal volume (no loud audio)
