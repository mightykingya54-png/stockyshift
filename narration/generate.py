"""Generate StockyShift listing video narration — one MP3 per scene.
Run: /var/folders/jb/19kw5s6102s7d4w9k1ddh_5r0000gn/T/opencode/tts-venv/bin/python3 generate.py
"""
import asyncio
from pathlib import Path

import edge_tts

VOICE = "en-US-AndrewNeural"
RATE = "-5%"  # calm, clear pacing for a product demo
OUT = Path(__file__).parent

SCENES = {
    "scene1": "Open StockyShift from your Shopify admin, and here's the first thing you see — everything you're about to run out of. Ceramic Mug: two left, reorder point five. Linen T-Shirt: four left, reorder point five. Both flagged before a customer ever hits an out-of-stock page. Canvas Tote's at fifteen — no alert. StockyShift only nags you when it matters.",
    "scene2": "Each product has its own reorder point — your minimum healthy stock. The Tote's at fifteen with a reorder point of ten — healthy, no alert. But say you want a bigger buffer. Set it to twenty, save — and watch, StockyShift flags it instantly. Set it once, and it watches from then on — daily automatic sync means your numbers are always current.",
    "scene3": "Add each supplier once — name and email — and they're stored and reused on every purchase order. No more hunting through old emails for who you bought your mugs from.",
    "scene4": "Now the part that saves you real time. One click on Order turns low stock into a purchase order. The quantity is already calculated — the deficit between what you have and what you need — and the supplier's already attached. No spreadsheets, no manual math, no retyping SKUs. Just create, and your PO is done.",
    "scene5": "Every purchase order exports as a clean CSV file — keep it for your records, or open it in the tools you already use. And when your supplier needs something more official, Send emails the PO straight to them with a ready-to-print PDF attached.",
    "scene6": "Pricing is simple — one plan, twenty-nine dollars a month, with a seven-day free trial. No tier gymnastics, no per-product fees. Manage or cancel right through Shopify, any time.",
    "scene7": "StockyShift. Stop running out of stock — and stop guessing what to reorder. Install it free from the Shopify App Store — and start your seven-day trial today.",
}


async def main():
    for name, text in SCENES.items():
        out = OUT / f"{name}.mp3"
        communicate = edge_tts.Communicate(text, VOICE, rate=RATE)
        await communicate.save(str(out))
        print(f"OK {out} ({out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    asyncio.run(main())
