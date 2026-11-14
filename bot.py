import asyncio, logging, os, time
from logging.handlers import RotatingFileHandler

import discord
from discord import app_commands
from discord.ext import tasks
from apscheduler.schedulers.asyncio import AsyncIOScheduler

import yaml
from dotenv import load_dotenv

from store import Store
from sources import run_source
from verifier import verify

load_dotenv()
with open("config.yaml") as f: CFG = yaml.safe_load(f)
with open("sources.yaml") as f: SOURCES = yaml.safe_load(f)["sources"]

LOG = logging.getLogger("bot")
LOG.setLevel(getattr(logging, CFG["logging"]["level"]))
fh = RotatingFileHandler(CFG["logging"]["file"], maxBytes=2_000_000, backupCount=3)
LOG.addHandler(fh); LOG.addHandler(logging.StreamHandler())

store = Store()
intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)
sched = AsyncIOScheduler(timezone="UTC")


# ---------------- scrape + verify cycle ----------------
async def run_cycle():
    LOG.info("cycle start")
    total_new = 0
    for src in SOURCES:
        try:
            ips = await asyncio.to_thread(run_source, src)
            added = 0
            for ip in ips:
                if store.upsert_host(ip, src["name"]):
                    added += 1
            store.mark_source(src["name"], "ok", len(ips))
            total_new += added
            LOG.info(f"{src['name']}: {len(ips)} seen, {added} new")
        except Exception as e:
            store.mark_source(src["name"], "error", 0, str(e))
            LOG.warning(f"{src['name']}: {e}")

    # verify unchecked candidates
    ips = store.unchecked(CFG["scraper"]["max_candidates_per_cycle"])
    if not ips:
        LOG.info("cycle end: no candidates to verify")
        return
    sem = asyncio.Semaphore(CFG["scraper"]["verify_concurrency"])

    async def check(ip):
        async with sem:
            return ip, await asyncio.to_thread(
                verify, ip,
                os.path.expanduser(CFG["verifier"]["key_db"]),
                CFG["scraper"]["verify_timeout"],
                CFG["verifier"]["beacon_wait"],
                os.environ.get("VERIFIER_LHOST"))

    tasks_list = [asyncio.create_task(check(ip)) for ip in ips]
    for coro in asyncio.as_completed(tasks_list):
        ip, (verdict, detail) = await coro
        store.set_verdict(ip, verdict, note=detail)
        if verdict == "confirmed":
            await post_confirmed(ip, detail)
        elif verdict == "possible":
            await post_candidate(ip, detail)


async def post_confirmed(ip, detail):
    ch = client.get_channel(CFG["discord"]["channels"]["confirmed"])
    if not ch: return
    embed = discord.Embed(title="CONFIRMED VULNERABLE", color=0x00ff00)
    embed.add_field(name="IP", value=f"`{ip}`", inline=True)
    embed.add_field(name="CVE", value="CVE-2024-36435", inline=True)
    embed.add_field(name="Evidence", value=detail[:1000], inline=False)
    embed.timestamp = discord.utils.utcnow()
    await ch.send(embed=embed)


async def post_candidate(ip, detail):
    ch = client.get_channel(CFG["discord"]["channels"]["candidates"])
    if not ch: return
    await ch.send(f"`{ip}` possible: {detail[:300]}")


@sched.scheduled_job("interval", minutes=CFG["scraper"]["interval_minutes"])
async def cycle_job():
    await run_cycle()


# ---------------- slash commands ----------------
@tree.command(description="Current scraper + verifier stats")
async def stats(itx: discord.Interaction):
    s = store.stats()
    e = discord.Embed(title="Scraper stats", color=0x3498db)
    e.add_field(name="Total hosts", value=str(s["total"]), inline=True)
    e.add_field(name="Confirmed", value=str(s["by_verdict"].get("confirmed", 0)), inline=True)
    e.add_field(name="Possible", value=str(s["by_verdict"].get("possible", 0)), inline=True)
    e.add_field(name="Unchecked", value=str(s["by_verdict"].get("unchecked", 0)), inline=True)
    src_lines = []
    for src in s["sources"]:
        src_lines.append(f"`{src['name']}` {src['last_status']} ({src['last_count']})")
    e.add_field(name="Sources", value="\n".join(src_lines)[:1000] or "none run yet", inline=False)
    await itx.response.send_message(embed=e)


@tree.command(description="List confirmed vulnerable IPs")
@app_commands.describe(limit="How many to show (max 50)")
async def confirmed(itx: discord.Interaction, limit: int = 20):
    limit = min(limit, 50)
    rows = store.by_verdict("confirmed", limit)
    if not rows:
        return await itx.response.send_message("No confirmed hits yet.")
    txt = "\n".join(f"`{r['ip']}` — {r['note']}" for r in rows)
    await itx.response.send_message(f"```\n{txt}\n```")


@tree.command(description="Verify a specific IP right now")
@app_commands.describe(ip="IPv4 address")
async def verify_one(itx: discord.Interaction, ip: str):
    await itx.response.defer(thinking=True)
    verdict, detail = await asyncio.to_thread(
        verify, ip, os.path.expanduser(CFG["verifier"]["key_db"]),
        CFG["scraper"]["verify_timeout"], CFG["verifier"]["beacon_wait"],
        os.environ.get("VERIFIER_LHOST"))
    store.upsert_host(ip, "manual")
    store.set_verdict(ip, verdict, note=detail)
    color = 0x00ff00 if verdict == "confirmed" else 0xffaa00 if verdict == "possible" else 0xff0000
    e = discord.Embed(title=f"{verdict.upper()}", color=color)
    e.add_field(name="IP", value=f"`{ip}`", inline=True)
    e.add_field(name="Detail", value=detail[:1000], inline=False)
    await itx.followup.send(embed=e)


@tree.command(description="Run a full scrape cycle now")
async def run_now(itx: discord.Interaction):
    await itx.response.send_message("cycle started", ephemeral=True)
    await run_cycle()


@tree.command(description="Run one source and report what it returned")
@app_commands.describe(name="Source name from sources.yaml")
async def test_source(itx: discord.Interaction, name: str):
    src = next((s for s in SOURCES if s["name"] == name), None)
    if not src:
        return await itx.response.send_message(f"unknown source `{name}`", ephemeral=True)
    await itx.response.defer(thinking=True)
    try:
        ips = await asyncio.to_thread(run_source, src)
        added = sum(store.upsert_host(ip, name) for ip in ips)
        store.mark_source(name, "ok", len(ips))
        await itx.followup.send(f"`{name}`: {len(ips)} seen, {added} new")
    except Exception as e:
        store.mark_source(name, "error", 0, str(e))
        await itx.followup.send(f"`{name}` error: {e}", ephemeral=True)


@tree.command(description="Export confirmed IPs to CSV")
async def export(itx: discord.Interaction):
    rows = store.by_verdict("confirmed", 5000)
    if not rows:
        return await itx.response.send_message("nothing to export", ephemeral=True)
    p = f"/tmp/confirmed_{int(time.time())}.csv"
    with open(p, "w") as f:
        f.write("ip,firmware,family,verdict_at,note\n")
        for r in rows:
            f.write(f"{r['ip']},{r['firmware']},{r['family']},{r['verdict_at']},{r['note']}\n")
    await itx.response.send_message(file=discord.File(p))


# ---------------- startup ----------------
@client.event
async def on_ready():
    gid = CFG["discord"].get("guild_id") or None
    if gid:
        g = discord.Object(id=gid)
        tree.copy_global_to(guild=g)
        await tree.sync(guild=g)
    else:
        await tree.sync()
    sched.add_job(cycle_job, "interval", minutes=CFG["scraper"]["interval_minutes"], id="cycle")
    sched.start()
    LOG.info(f"ready as {client.user}")


if __name__ == "__main__":
    client.run(os.environ["DISCORD_TOKEN"])
