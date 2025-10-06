"""
EagleNode Host - Discord Bot (Updated)
Provides slash-command based VPS/container management backed by Docker.
- Slash commands (app_commands) are the primary interface (prefix "/" as requested).
- Uses docker SDK (docker-py) for container operations.
- Backup/restore for container metadata.
- Admin checks and per-user limits enforced.
- Extensive logging and inline comments.

Requirements:
- python-dotenv
- discord.py (2.x) with intents
- docker (docker-py)
- aiohttp, flask, flask_socketio (optional dashboard)
"""

import os
import asyncio
import logging
import json
import pickle
import datetime
from typing import Optional, Dict, Any, List

import discord
from discord import app_commands
from discord.ext import commands

import docker
from docker.errors import DockerException, NotFound, APIError

# ---------------------------
# Configuration (env-driven)
# ---------------------------
from dotenv import load_dotenv
load_dotenv()

# Bot & Admin config
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
if not DISCORD_TOKEN:
    raise RuntimeError("DISCORD_TOKEN not set in environment")

# Comma-separated admin ids
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()}
ADMIN_ROLE_ID = int(os.getenv("ADMIN_ROLE_ID", "0")) if os.getenv("ADMIN_ROLE_ID") else None

# Limits & defaults
MAX_VPS_PER_USER = int(os.getenv("MAX_VPS_PER_USER", "3"))
DEFAULT_OS_IMAGE = os.getenv("DEFAULT_OS_IMAGE", "ubuntu:22.04")
DOCKER_NETWORK = os.getenv("DOCKER_NETWORK", "bridge")
MAX_CONTAINERS = int(os.getenv("MAX_CONTAINERS", "100"))
BACKUP_FILE = os.getenv("BACKUP_FILE", "eaglenode_backup.pkl")
DB_FILE = os.getenv("DB_FILE", "eaglenode.db")

# Watermark / messages
WATERMARK = os.getenv("WATERMARK", "EagleNode Host VPS Service")
WELCOME_MESSAGE = os.getenv("WELCOME_MESSAGE", "Welcome To EagleNode Host! Get Started With Us!")

# Miner patterns (to help detect/deny suspicious containers)
MINER_PATTERNS = [
    'xmrig', 'ethminer', 'cgminer', 'sgminer', 'bfgminer',
    'minerd', 'cpuminer', 'cryptonight', 'stratum', 'pool'
]

# Logging
LOG_FILE = os.getenv("LOG_FILE", "eaglenode_bot.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("EagleNodeHostBot")

# ---------------------------
# Docker client initialization
# ---------------------------
try:
    docker_client = docker.from_env()
    docker_client.ping()
except Exception as e:
    logger.exception("Failed to initialize Docker client: %s", e)
    docker_client = None  # Bot will handle missing docker gracefully

# ---------------------------
# State management
# ---------------------------
# Simple in-memory mapping with backup; persistent DB support can be added later.
# Structure: {container_name: {owner_id:int, image:str, created_at:iso, metadata: {...}}}
vps_state: Dict[str, Dict[str, Any]] = {}

def load_backup():
    global vps_state
    if os.path.exists(BACKUP_FILE):
        try:
            with open(BACKUP_FILE, "rb") as f:
                vps_state = pickle.load(f)
                logger.info("Loaded backup from %s (%d entries)", BACKUP_FILE, len(vps_state))
        except Exception as e:
            logger.exception("Failed to load backup file: %s", e)
    else:
        logger.info("No backup file found (%s). Starting with empty state.", BACKUP_FILE)

def save_backup():
    try:
        with open(BACKUP_FILE, "wb") as f:
            pickle.dump(vps_state, f)
        logger.info("Saved backup to %s (%d entries)", BACKUP_FILE, len(vps_state))
    except Exception as e:
        logger.exception("Failed to save backup: %s", e)

# load on startup
load_backup()

# ---------------------------
# Utilities
# ---------------------------
def is_admin(user: discord.User) -> bool:
    if user.id in ADMIN_IDS:
        return True
    # If ADMIN_ROLE_ID is set, membership check on guild required (done in command context)
    return False

async def member_is_admin(interaction: discord.Interaction) -> bool:
    """Check admin by ID or role in the guild where the interaction happened."""
    if interaction.user.id in ADMIN_IDS:
        return True
    if ADMIN_ROLE_ID and isinstance(interaction.user, discord.Member):
        return any(r.id == ADMIN_ROLE_ID for r in interaction.user.roles)
    return False

def safe_container_name(base: str, uid: int) -> str:
    """Make a deterministic and safe container name."""
    name = f"eaglenode-{base}-{uid}"
    # sanitize any spaces or bad chars
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in name.lower())

def detect_malicious_image(image: str) -> bool:
    """Simple heuristic: detect miner strings in image name."""
    lower = image.lower()
    return any(patt in lower for patt in MINER_PATTERNS)

async def run_docker_container(image: str, name: str, owner_id: int, env: Optional[Dict[str,str]]=None, cpu_limit: Optional[float]=None, mem_limit: Optional[str]=None) -> dict:
    """Create and start a Docker container using the docker SDK."""
    if docker_client is None:
        raise RuntimeError("Docker client not available on host")

    # Build host_config kwargs (resource constraints)
    host_config = {}
    # Example: mem_limit could be "512m", "1g" - docker-py accepts strings
    if mem_limit:
        host_config['mem_limit'] = mem_limit
    if cpu_limit:
        host_config['cpu_quota'] = int(cpu_limit * 100000)  # convert to microseconds (approx.)

    # Environment
    environment = env or {}
    environment.update({
        "WELCOME_MESSAGE": WELCOME_MESSAGE,
        "WATERMARK": WATERMARK
    })

    logger.info("Creating container %s from image %s (owner=%s)", name, image, owner_id)
    try:
        # Pull image if necessary
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
            labels={"eaglenode_owner": str(owner_id), "eaglenode": "true"},
            **host_config
        )
        logger.info("Started container %s (id=%s)", name, container.short_id)
        return {"id": container.id, "short_id": container.short_id}
    except APIError as api_err:
        logger.exception("Docker API error: %s", api_err)
        raise
    except DockerException as docker_err:
        logger.exception("Docker error: %s", docker_err)
        raise

# ---------------------------
# Discord Bot Setup
# ---------------------------
intents = discord.Intents.default()
intents.message_content = True  # only needed if you want prefix commands reading message content
bot = commands.Bot(command_prefix="!", intents=intents)  # prefix kept for optional legacy
tree = bot.tree  # alias

# Helper decorator for admin-only application commands
def admin_only():
    def predicate(interaction: discord.Interaction) -> bool:
        # synchronous checks can run here, but we'll rely on async check where needed
        return True
    return app_commands.check(lambda i: True)

# ---------------------------
# App command implementations
# ---------------------------
@tree.command(name="ping", description="Check bot responsiveness")
async def slash_ping(interaction: discord.Interaction):
    await interaction.response.send_message("Pong! 🦅", ephemeral=True)

@tree.command(name="create", description="Create a new VPS (Docker container).")
@app_commands.describe(name="name for the VPS", image="Docker image (e.g. ubuntu:22.04)", memory="Memory limit (e.g. 512m)", cpus="CPU limit (e.g. 0.5)")
async def slash_create(interaction: discord.Interaction, name: str, image: Optional[str]=DEFAULT_OS_IMAGE, memory: Optional[str]=None, cpus: Optional[float]=None):
    await interaction.response.defer(thinking=True)
    user = interaction.user
    # enforce per-user limit
    user_containers = [n for n, v in vps_state.items() if v.get("owner_id") == user.id]
    if len(user_containers) >= MAX_VPS_PER_USER:
        await interaction.followup.send(f"You already have {len(user_containers)} VPSs (limit {MAX_VPS_PER_USER}). Delete one before creating another.", ephemeral=True)
        return

    sanitized_name = safe_container_name(name, user.id)
    if sanitized_name in vps_state:
        await interaction.followup.send("A container with that name already exists in the managed state. Choose a different name.", ephemeral=True)
        return

    if detect_malicious_image(image):
        await interaction.followup.send("The chosen image looks suspicious (miner-like). Operation denied.", ephemeral=True)
        return

    # global container cap
    if len(vps_state) >= MAX_CONTAINERS:
        await interaction.followup.send("Host reached maximum managed container count. Try again later or contact admin.", ephemeral=True)
        return

    try:
        res = await asyncio.to_thread(run_docker_container, image, sanitized_name, user.id, None, cpus, memory)
        # record to state
        vps_state[sanitized_name] = {
            "owner_id": user.id,
            "image": image,
            "created_at": datetime.datetime.utcnow().isoformat(),
            "container_id": res.get("id"),
            "short_id": res.get("short_id"),
            "meta": {}
        }
        save_backup()
        await interaction.followup.send(f"✅ VPS **{sanitized_name}** created and started (image: `{image}`).", ephemeral=False)
    except Exception as e:
        logger.exception("Failed to create container: %s", e)
        await interaction.followup.send(f"❌ Failed to create VPS: {e}", ephemeral=True)

@tree.command(name="list", description="List your VPS containers managed by EagleNode")
async def slash_list(interaction: discord.Interaction):
    user = interaction.user
    # gather containers owned by user
    owned = {n: v for n, v in vps_state.items() if v.get("owner_id") == user.id}
    if not owned:
        await interaction.response.send_message("You have no VPS instances managed by EagleNode.", ephemeral=True)
        return

    lines = []
    for name, meta in owned.items():
        cid = meta.get("short_id") or meta.get("container_id", "unknown")
        image = meta.get("image")
        created = meta.get("created_at")
        # attempt to get runtime status
        status = "unknown"
        try:
            container = docker_client.containers.get(meta.get("container_id"))
            status = container.status
        except Exception:
            status = "not found"
        lines.append(f"**{name}** — `{cid}` — `{image}` — `{status}` — created {created}")

    await interaction.response.send_message("\n".join(lines), ephemeral=True)

@tree.command(name="status", description="Get status of a managed VPS")
@app_commands.describe(name="Name of your VPS (exact)")
async def slash_status(interaction: discord.Interaction, name: str):
    await interaction.response.defer(thinking=True)
    entry = vps_state.get(name)
    if not entry:
        await interaction.followup.send("No managed VPS with that name.", ephemeral=True)
        return
    try:
        container = docker_client.containers.get(entry.get("container_id"))
        info = {
            "id": container.short_id,
            "status": container.status,
            "image": container.image.tags,
            "created": container.attrs.get("Created"),
        }
        await interaction.followup.send(f"**{name}** — `{info['id']}` — status: `{info['status']}` — image: `{info['image']}`", ephemeral=True)
    except NotFound:
        await interaction.followup.send("Container not found on host (maybe removed manually).", ephemeral=True)
    except Exception as e:
        logger.exception("Status check failed: %s", e)
        await interaction.followup.send(f"Error getting status: {e}", ephemeral=True)

@tree.command(name="start", description="Start a stopped VPS")
@app_commands.describe(name="Name of your VPS")
async def slash_start(interaction: discord.Interaction, name: str):
    await interaction.response.defer(thinking=True)
    entry = vps_state.get(name)
    if not entry:
        await interaction.followup.send("No managed VPS with that name.", ephemeral=True)
        return
    # permisssion: owner or admin
    if entry.get("owner_id") != interaction.user.id and not await member_is_admin(interaction):
        await interaction.followup.send("Only the owner or an admin can start this VPS.", ephemeral=True)
        return
    try:
        container = docker_client.containers.get(entry.get("container_id"))
        container.start()
        await interaction.followup.send(f"✅ VPS **{name}** started.", ephemeral=True)
    except NotFound:
        await interaction.followup.send("Container not found on host.", ephemeral=True)
    except Exception as e:
        logger.exception("Failed to start container: %s", e)
        await interaction.followup.send(f"Failed to start VPS: {e}", ephemeral=True)

@tree.command(name="stop", description="Stop a running VPS")
@app_commands.describe(name="Name of your VPS")
async def slash_stop(interaction: discord.Interaction, name: str):
    await interaction.response.defer(thinking=True)
    entry = vps_state.get(name)
    if not entry:
        await interaction.followup.send("No managed VPS with that name.", ephemeral=True)
        return
    if entry.get("owner_id") != interaction.user.id and not await member_is_admin(interaction):
        await interaction.followup.send("Only the owner or an admin can stop this VPS.", ephemeral=True)
        return
    try:
        container = docker_client.containers.get(entry.get("container_id"))
        container.stop()
        await interaction.followup.send(f"✅ VPS **{name}** stopped.", ephemeral=True)
    except NotFound:
        await interaction.followup.send("Container not found on host.", ephemeral=True)
    except Exception as e:
        logger.exception("Failed to stop container: %s", e)
        await interaction.followup.send(f"Failed to stop VPS: {e}", ephemeral=True)

@tree.command(name="restart", description="Restart a VPS")
@app_commands.describe(name="Name of your VPS")
async def slash_restart(interaction: discord.Interaction, name: str):
    await interaction.response.defer(thinking=True)
    entry = vps_state.get(name)
    if not entry:
        await interaction.followup.send("No managed VPS with that name.", ephemeral=True)
        return
    if entry.get("owner_id") != interaction.user.id and not await member_is_admin(interaction):
        await interaction.followup.send("Only the owner or an admin can restart this VPS.", ephemeral=True)
        return
    try:
        container = docker_client.containers.get(entry.get("container_id"))
        container.restart()
        await interaction.followup.send(f"✅ VPS **{name}** restarted.", ephemeral=True)
    except NotFound:
        await interaction.followup.send("Container not found on host.", ephemeral=True)
    except Exception as e:
        logger.exception("Failed to restart container: %s", e)
        await interaction.followup.send(f"Failed to restart VPS: {e}", ephemeral=True)

@tree.command(name="delete", description="Delete (remove) a managed VPS")
@app_commands.describe(name="Name of the VPS to delete")
async def slash_delete(interaction: discord.Interaction, name: str, force: bool = False):
    await interaction.response.defer(thinking=True)
    entry = vps_state.get(name)
    if not entry:
        await interaction.followup.send("No managed VPS with that name.", ephemeral=True)
        return
    if entry.get("owner_id") != interaction.user.id and not await member_is_admin(interaction):
        await interaction.followup.send("Only the owner or an admin can delete this VPS.", ephemeral=True)
        return

    try:
        # Attempt to remove container if exists
        try:
            container = docker_client.containers.get(entry.get("container_id"))
            container.remove(force=force)
            logger.info("Removed container %s (force=%s)", name, force)
        except NotFound:
            logger.info("Container not found on removal, proceeding to cleanup state.")

        # cleanup state
        vps_state.pop(name, None)
        save_backup()
        await interaction.followup.send(f"🗑️ VPS **{name}** removed and state cleaned.", ephemeral=True)
    except Exception as e:
        logger.exception("Failed to delete container: %s", e)
        await interaction.followup.send(f"Failed to delete VPS: {e}", ephemeral=True)

@tree.command(name="exec", description="Execute a command inside a running VPS container")
@app_commands.describe(name="VPS name", command="Command to execute (e.g. ls -la /)")
async def slash_exec(interaction: discord.Interaction, name: str, command: str):
    await interaction.response.defer(thinking=True)
    entry = vps_state.get(name)
    if not entry:
        await interaction.followup.send("No managed VPS with that name.", ephemeral=True)
        return
    if entry.get("owner_id") != interaction.user.id and not await member_is_admin(interaction):
        await interaction.followup.send("Only the owner or an admin can exec inside this VPS.", ephemeral=True)
        return
    try:
        container = docker_client.containers.get(entry.get("container_id"))
        exec_ins = container.exec_run(cmd=["/bin/bash", "-lc", command], stdout=True, stderr=True, demux=True)
        stdout, stderr = exec_ins.output if isinstance(exec_ins.output, tuple) else (exec_ins.output, b"")
        out_text = (stdout or b"").decode(errors="ignore")
        err_text = (stderr or b"").decode(errors="ignore")
        combined = (out_text + "\n" + err_text).strip()
        if len(combined) == 0:
            combined = "(no output)"
        # Discord message length limit handling
        if len(combined) > 1900:
            combined = combined[:1900] + "\n...truncated..."
        await interaction.followup.send(f"```\n{combined}\n```", ephemeral=True)
    except NotFound:
        await interaction.followup.send("Container not found on host.", ephemeral=True)
    except Exception as e:
        logger.exception("Exec failed: %s", e)
        await interaction.followup.send(f"Exec failed: {e}", ephemeral=True)

# ---------------------------
# Admin-only commands
# ---------------------------
@tree.command(name="backup", description="Create a backup of the managed state (admin only)")
@app_commands.checks.has_permissions(administrator=True)
async def slash_backup(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True)
    try:
        save_backup()
        await interaction.followup.send(f"✅ Backup saved to `{BACKUP_FILE}`.", ephemeral=True)
    except Exception as e:
        logger.exception("Backup failed: %s", e)
        await interaction.followup.send(f"Backup failed: {e}", ephemeral=True)

@tree.command(name="restore", description="Restore managed state from backup (admin only)")
@app_commands.checks.has_permissions(administrator=True)
async def slash_restore(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True)
    try:
        load_backup()
        await interaction.followup.send("✅ Restored state from backup.", ephemeral=True)
    except Exception as e:
        logger.exception("Restore failed: %s", e)
        await interaction.followup.send(f"Restore failed: {e}", ephemeral=True)

@tree.command(name="health-check", description="Run a host health check (admin only)")
@app_commands.checks.has_permissions(administrator=True)
async def slash_health_check(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True)
    try:
        info = {}
        try:
            info['docker'] = "available" if docker_client and docker_client.ping() is None else "available"
        except Exception:
            info['docker'] = "unavailable"
        # Add resource usage checks if psutil is available
        try:
            import psutil
            info['cpu_percent'] = psutil.cpu_percent(interval=0.5)
            info['mem_percent'] = psutil.virtual_memory().percent
        except Exception:
            info['sys_resources'] = "psutil not available"
        await interaction.followup.send(f"Health check: ```{json.dumps(info, indent=2)}```", ephemeral=True)
    except Exception as e:
        logger.exception("Health check failed: %s", e)
        await interaction.followup.send(f"Health check failed: {e}", ephemeral=True)

# ---------------------------
# Event handlers & sync
# ---------------------------
@bot.event
async def on_ready():
    logger.info("Logged in as %s (id=%s)", bot.user, bot.user.id)
    try:
        # Sync commands to all guilds (be careful in production; consider guild-specific sync)
        await tree.sync()
        logger.info("Slash commands synced.")
    except Exception as e:
        logger.exception("Failed to sync commands: %s", e)

@bot.event
async def on_command_error(ctx, error):
    logger.exception("Command error: %s", error)
    # Send a friendly message
    try:
        await ctx.send(f"Error: {error}")
    except Exception:
        pass

@bot.event
async def on_app_command_error(interaction: discord.Interaction, error):
    logger.exception("App command error: %s", error)
    try:
        await interaction.response.send_message(f"Error: {error}", ephemeral=True)
    except Exception:
        pass

# ---------------------------
# Optional: simple legacy prefix commands (kept minimal)
# ---------------------------
@bot.command(name="create_legacy")
async def legacy_create(ctx, name: str, image: Optional[str] = DEFAULT_OS_IMAGE):
    """Legacy prefix command: !create_legacy NAME [IMAGE]"""
    await ctx.send("Please use the slash command `/create` instead.", ephemeral=True)

# ---------------------------
# Graceful shutdown helper
# ---------------------------
async def shutdown_bot():
    logger.info("Shutting down bot and saving state...")
    save_backup()
    try:
        await bot.close()
    except Exception:
        pass

# ---------------------------
# Entrypoint
# ---------------------------
if __name__ == "__main__":
    # Safety checks
    if docker_client is None:
        logger.warning("Docker client is not available. Many operations will fail until Docker is reachable.")
    try:
        bot.run(DISCORD_TOKEN)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Exiting.")
        asyncio.run(shutdown_bot())
    except Exception as e:
        logger.exception("Fatal error in bot.run(): %s", e)
        save_backup()
