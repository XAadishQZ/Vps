"""
EagleNode Host - Discord Bot (Fixed + DM VPS Info)
"""

import os
import asyncio
import logging
import pickle
import datetime
from typing import Optional, Dict, Any

import discord
from discord import app_commands
from discord.ext import commands

import docker
from docker.errors import DockerException, NotFound, APIError
from dotenv import load_dotenv

load_dotenv()

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
if not DISCORD_TOKEN:
    raise RuntimeError("DISCORD_TOKEN not set")

ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()}
ADMIN_ROLE_ID = int(os.getenv("ADMIN_ROLE_ID", "0")) if os.getenv("ADMIN_ROLE_ID") else None

MAX_VPS_PER_USER = int(os.getenv("MAX_VPS_PER_USER", "3"))
DEFAULT_OS_IMAGE = os.getenv("DEFAULT_OS_IMAGE", "ubuntu:22.04")
DOCKER_NETWORK = os.getenv("DOCKER_NETWORK", "bridge")
MAX_CONTAINERS = int(os.getenv("MAX_CONTAINERS", "100"))
BACKUP_FILE = os.getenv("BACKUP_FILE", "eaglenode_backup.pkl")

WATERMARK = os.getenv("WATERMARK", "EagleNode Host VPS Service")
WELCOME_MESSAGE = os.getenv("WELCOME_MESSAGE", "Welcome To EagleNode Host! Get Started With Us!")

LOG_FILE = os.getenv("LOG_FILE", "eaglenode_bot.log")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("EagleNodeHostBot")

try:
    docker_client = docker.from_env()
    docker_client.ping()
except Exception as e:
    docker_client = None
    logger.exception("Docker unavailable: %s", e)

vps_state: Dict[str, Dict[str, Any]] = {}

def save_backup():
    with open(BACKUP_FILE, "wb") as f:
        pickle.dump(vps_state, f)

def load_backup():
    global vps_state
    if os.path.exists(BACKUP_FILE):
        with open(BACKUP_FILE, "rb") as f:
            vps_state = pickle.load(f)

load_backup()

def safe_container_name(base: str, uid: int) -> str:
    return "eaglenode-" + "".join(c if c.isalnum() else "-" for c in f"{base}-{uid}").lower()

def detect_malicious_image(image: str) -> bool:
    patterns = ["xmrig", "miner", "cryptonight", "stratum", "pool"]
    return any(p in image.lower() for p in patterns)

def run_docker_container(image: str, name: str, owner_id: int,
                         env: Optional[Dict[str, str]] = None,
                         cpu_limit: Optional[float] = None,
                         mem_limit: Optional[str] = None) -> dict:
    if docker_client is None:
        raise RuntimeError("Docker client not available")

    host_config = {}
    if mem_limit:
        host_config["mem_limit"] = mem_limit
    if cpu_limit:
        host_config["cpu_quota"] = int(cpu_limit * 100000)

    environment = env or {}
    environment.update({"WELCOME_MESSAGE": WELCOME_MESSAGE, "WATERMARK": WATERMARK})

    docker_client.images.pull(image)
    container = docker_client.containers.run(
        image=image,
        name=name,
        detach=True,
        network=DOCKER_NETWORK,
        environment=environment,
        stdin_open=True,
        tty=True,
        hostname=name,
        labels={"eaglenode_owner": str(owner_id)},
        **host_config
    )
    return {"id": container.id, "short_id": container.short_id}

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

async def member_is_admin(interaction: discord.Interaction) -> bool:
    if interaction.user.id in ADMIN_IDS:
        return True
    if ADMIN_ROLE_ID and isinstance(interaction.user, discord.Member):
        return any(r.id == ADMIN_ROLE_ID for r in interaction.user.roles)
    return False

@tree.command(name="ping", description="Check bot ping")
async def ping_cmd(interaction: discord.Interaction):
    await interaction.response.send_message("🦅 Pong! EagleNode Bot is active.", ephemeral=True)

@tree.command(name="create", description="Create a new VPS (Docker container) and receive details via DM.")
@app_commands.describe(name="VPS name", image="Docker image", memory="Memory limit (e.g. 512m)", cpus="CPU limit (e.g. 0.5)")
async def create_cmd(interaction: discord.Interaction, name: str, image: Optional[str] = DEFAULT_OS_IMAGE,
                     memory: Optional[str] = None, cpus: Optional[float] = None):
    await interaction.response.defer(thinking=True)
    user = interaction.user

    owned = [n for n, v in vps_state.items() if v["owner_id"] == user.id]
    if len(owned) >= MAX_VPS_PER_USER:
        await interaction.followup.send("❌ VPS limit reached.", ephemeral=True)
        return

    cname = safe_container_name(name, user.id)
    if cname in vps_state:
        await interaction.followup.send("❌ VPS name already exists.", ephemeral=True)
        return

    if detect_malicious_image(image):
        await interaction.followup.send("⚠️ Image blocked (miner detected).", ephemeral=True)
        return

    try:
        res = await asyncio.to_thread(run_docker_container, image, cname, user.id, None, cpus, memory)
        vps_state[cname] = {
            "owner_id": user.id,
            "image": image,
            "created_at": datetime.datetime.utcnow().isoformat(),
            "container_id": res["id"],
            "short_id": res["short_id"]
        }
        save_backup()

        # ✅ DM VPS details to user
        try:
            dm_msg = (
                f"🦅 **EagleNode VPS Created Successfully!**\n\n"
                f"**VPS Name:** {cname}\n"
                f"**Image:** {image}\n"
                f"**Container ID:** {res['short_id']}\n"
                f"**Status:** Running\n"
                f"**Created:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n"
                f"Thank you for using **EagleNode Host VPS Service** 🦅"
            )
            await user.send(dm_msg)
        except discord.Forbidden:
            await interaction.followup.send("⚠️ Could not DM VPS info (user has DMs disabled).", ephemeral=True)

        await interaction.followup.send(f"✅ VPS **{cname}** created successfully. Details sent via DM.", ephemeral=False)
    except Exception as e:
        logger.exception("Error creating VPS: %s", e)
        await interaction.followup.send(f"❌ Failed to create VPS: {e}", ephemeral=True)

@bot.event
async def on_ready():
    await tree.sync()
    logger.info("EagleNode bot logged in as %s", bot.user)

if __name__ == "__main__":
    bot.run(DISCORD_TOKEN)
