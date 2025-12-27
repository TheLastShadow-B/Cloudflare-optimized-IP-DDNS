#!/usr/bin/env python3
"""
HE.net DNS A 记录自动更新工具

从 vps789.com 获取 Cloudflare 优化 IP 的 Top 20 域名，
筛选丢包率低于阈值的域名，解析所有 IP 并去重，
对 IP 进行 ping 测试后选择最佳的 1 个 IP 更新 dns.he.net 的 A 记录。

配置文件: .env（与脚本同目录）
运行方式: python he_dns_updater.py（无需任何参数）

作者: Claude Code
日期: 2025-12-27
"""

import sys
import subprocess
import platform
import re
import socket
import struct
import requests
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

# 尝试导入 dnspython，如果没有则使用 nslookup 命令
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# 脚本所在目录
SCRIPT_DIR = Path(__file__).parent.absolute()
ENV_FILE = SCRIPT_DIR / '.env'

# .env 文件模板
ENV_TEMPLATE = """# HE.net DNS 自动更新工具配置文件
# 请填写以下配置项后保存

# [必填] dns.he.net 上要更新的主机名（如: cdn.example.com）
HE_HOSTNAME=

# [必填] dns.he.net 动态 DNS 密钥
HE_PASSWORD=

# [可选] 每个 IP 的 ping 次数（默认: 100）
PING_COUNT=100

# [可选] 并发测试线程数（默认: 5）
PING_WORKERS=5

# [可选] 获取域名列表的 API 地址（默认使用 vps789.com）
API_URL=https://vps789.com/public/sum/cfIpTop20

# [可选] 丢包率筛选阈值，低于此值的域名才会被解析（默认: 0.5）
PKG_LOST_THRESHOLD=0.5

# [可选] DNS 服务器列表，用逗号分隔（默认: 119.29.29.29,223.5.5.5）
DNS_SERVERS=119.29.29.29,223.5.5.5

# [可选] 是否跳过本地 ping 测试，直接使用 API 数据（true/false，默认: false）
SKIP_PING=false

# [可选] 是否启用调试模式（true/false，默认: false）
DEBUG=false

# ============ CloudflareSpeedTest (cfst) 速度测试配置 ============

# [必填] cfst 测速地址（必须指定，建议自建测速地址）
# 该地址用于下载测速，应该是一个支持 Cloudflare CDN 的文件地址
CFST_URL=

# [可选] cfst 工具路径（默认: 与脚本同目录下的 cfst 或 cfst.exe）
# 如果工具不存在，会自动从 GitHub 下载
CFST_PATH=

# [可选] 进入速度测试的 IP 数量（默认: 8，从 ping 测试结果中选取前 N 个）
CFST_TOP_COUNT=8

# [可选] 速度测试超时时间，单位秒（默认: 10）
CFST_TIMEOUT=10

# [可选] 速度测试端口（默认: 443）
CFST_PORT=443
"""

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class Config:
    """配置类"""
    hostname: str
    password: str
    ping_count: int = 100
    ping_workers: int = 5
    api_url: str = "https://vps789.com/public/sum/cfIpTop20"
    pkg_lost_threshold: float = 0.5
    dns_servers: list[str] = field(default_factory=lambda: ['119.29.29.29', '223.5.5.5'])
    skip_ping: bool = False
    debug: bool = False
    # cfst 速度测试配置
    cfst_url: str = ""  # 测速地址（必填）
    cfst_path: str = ""  # cfst 工具路径（可选）
    cfst_top_count: int = 8  # 进入速度测试的 IP 数量
    cfst_timeout: int = 10  # 速度测试超时时间
    cfst_port: int = 443  # 速度测试端口


@dataclass
class PingResult:
    """Ping 测试结果"""
    ip: str
    source_domains: list[str] = field(default_factory=list)
    packets_sent: int = 0
    packets_received: int = 0
    packet_loss: float = 100.0
    min_latency: float = float('inf')
    avg_latency: float = float('inf')
    max_latency: float = float('inf')
    success: bool = False


@dataclass
class SpeedTestResult:
    """速度测试结果"""
    ip: str
    download_speed: float = 0.0  # MB/s
    avg_latency: float = float('inf')  # ms
    success: bool = False


@dataclass
class DomainInfo:
    """域名信息（来自 API）"""
    domain: str
    avg_latency: float
    avg_pkg_lost_rate: float
    score: float


def load_env_file(env_path: Path) -> dict:
    """
    加载 .env 文件

    Args:
        env_path: .env 文件路径

    Returns:
        环境变量字典
    """
    env_vars = {}

    if not env_path.exists():
        return env_vars

    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # 跳过空行和注释
            if not line or line.startswith('#'):
                continue
            # 解析 KEY=VALUE
            if '=' in line:
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip()
                # 移除引号
                if value and value[0] in ('"', "'") and value[-1] == value[0]:
                    value = value[1:-1]
                env_vars[key] = value

    return env_vars


def create_env_template(env_path: Path) -> None:
    """
    创建 .env 模板文件

    Args:
        env_path: .env 文件路径
    """
    with open(env_path, 'w', encoding='utf-8') as f:
        f.write(ENV_TEMPLATE)
    logger.info(f"已创建配置文件模板: {env_path}")


def load_config() -> Optional[Config]:
    """
    加载配置

    优先从 .env 文件读取，如果不存在则创建模板

    Returns:
        Config 对象，配置无效时返回 None
    """
    # 检查 .env 文件是否存在
    if not ENV_FILE.exists():
        create_env_template(ENV_FILE)
        logger.error(f"配置文件不存在，已创建模板: {ENV_FILE}")
        logger.error("请编辑配置文件填写必要参数后重新运行")
        return None

    # 加载 .env 文件
    env_vars = load_env_file(ENV_FILE)

    # 检查必填项
    hostname = env_vars.get('HE_HOSTNAME', '').strip()
    password = env_vars.get('HE_PASSWORD', '').strip()

    if not hostname:
        logger.error("配置文件缺少必填项: HE_HOSTNAME 未填写")
        logger.error(f"请编辑配置文件: {ENV_FILE}")
        return None

    if not password:
        logger.error("配置文件缺少必填项: HE_PASSWORD 未填写")
        logger.error(f"请编辑配置文件: {ENV_FILE}")
        return None

    # 解析可选配置
    def parse_bool(value: str, default: bool = False) -> bool:
        if not value:
            return default
        return value.lower() in ('true', '1', 'yes', 'on')

    def parse_int(value: str, default: int) -> int:
        if not value:
            return default
        try:
            return int(value)
        except ValueError:
            return default

    def parse_float(value: str, default: float) -> float:
        if not value:
            return default
        try:
            return float(value)
        except ValueError:
            return default

    def parse_list(value: str, default: list) -> list:
        if not value:
            return default
        return [item.strip() for item in value.split(',') if item.strip()]

    # 解析 DNS 服务器列表
    dns_servers_str = env_vars.get('DNS_SERVERS', '').strip()
    dns_servers = parse_list(dns_servers_str, ['119.29.29.29', '223.5.5.5'])

    config = Config(
        hostname=hostname,
        password=password,
        ping_count=parse_int(env_vars.get('PING_COUNT', ''), 100),
        ping_workers=parse_int(env_vars.get('PING_WORKERS', ''), 5),
        api_url=env_vars.get('API_URL', '').strip() or "https://vps789.com/public/sum/cfIpTop20",
        pkg_lost_threshold=parse_float(env_vars.get('PKG_LOST_THRESHOLD', ''), 0.5),
        dns_servers=dns_servers,
        skip_ping=parse_bool(env_vars.get('SKIP_PING', ''), False),
        debug=parse_bool(env_vars.get('DEBUG', ''), False),
        # cfst 速度测试配置
        cfst_url=env_vars.get('CFST_URL', '').strip(),
        cfst_path=env_vars.get('CFST_PATH', '').strip(),
        cfst_top_count=parse_int(env_vars.get('CFST_TOP_COUNT', ''), 8),
        cfst_timeout=parse_int(env_vars.get('CFST_TIMEOUT', ''), 10),
        cfst_port=parse_int(env_vars.get('CFST_PORT', ''), 443),
    )

    return config


def get_cfst_tool_path(config_path: str = "") -> Path:
    """
    获取 cfst 工具路径

    Args:
        config_path: 用户指定的工具路径

    Returns:
        cfst 工具的 Path 对象
    """
    if config_path:
        return Path(config_path)

    # 默认使用脚本所在目录
    system = platform.system().lower()
    if system == 'windows':
        return SCRIPT_DIR / 'cfst.exe'
    else:
        return SCRIPT_DIR / 'cfst'


def get_cfst_download_url() -> tuple[str, str]:
    """
    根据当前系统获取 cfst 下载地址

    Returns:
        (下载地址, 文件名) 元组
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    # 映射架构名称
    arch_map = {
        'x86_64': 'amd64',
        'amd64': 'amd64',
        'x64': 'amd64',
        'arm64': 'arm64',
        'aarch64': 'arm64',
        'armv7l': 'armv7',
        'armv6l': 'armv6',
        'armv5l': 'armv5',
        'i386': '386',
        'i686': '386',
    }
    arch = arch_map.get(machine, 'amd64')

    # 映射系统名称
    os_map = {
        'darwin': 'darwin',
        'linux': 'linux',
        'windows': 'windows',
    }
    os_name = os_map.get(system, 'linux')

    # 构建文件名（cfst_ 前缀）
    # Linux 使用 .tar.gz，macOS 和 Windows 使用 .zip
    if os_name == 'linux':
        filename = f"cfst_linux_{arch}.tar.gz"
    else:
        filename = f"cfst_{os_name}_{arch}.zip"

    # GitHub 最新版本下载地址
    base_url = "https://github.com/XIU2/CloudflareSpeedTest/releases/latest/download"
    download_url = f"{base_url}/{filename}"

    return download_url, filename


def download_cfst_tool(target_path: Path) -> bool:
    """
    从 GitHub 下载 cfst 工具

    Args:
        target_path: 工具保存路径

    Returns:
        是否下载成功
    """
    import tarfile
    import zipfile
    import tempfile

    download_url, filename = get_cfst_download_url()
    logger.info(f"正在下载 CloudflareSpeedTest: {download_url}")

    try:
        # 下载文件
        response = requests.get(download_url, stream=True, timeout=60)
        response.raise_for_status()

        # 保存到临时文件
        with tempfile.NamedTemporaryFile(delete=False, suffix=filename) as tmp_file:
            for chunk in response.iter_content(chunk_size=8192):
                tmp_file.write(chunk)
            tmp_path = tmp_file.name

        logger.info("下载完成，正在解压...")

        # 解压文件
        system = platform.system().lower()
        extract_dir = target_path.parent
        extracted = False

        if filename.endswith('.tar.gz'):
            with tarfile.open(tmp_path, 'r:gz') as tar:
                # 查找可执行文件
                for member in tar.getmembers():
                    if member.name.endswith('CloudflareST') or member.name == 'CloudflareST':
                        member.name = target_path.name
                        tar.extract(member, extract_dir)
                        extracted = True
                        break
        elif filename.endswith('.zip'):
            with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
                for name in zip_ref.namelist():
                    # Windows: CloudflareST.exe, macOS: CloudflareST
                    base_name = name.split('/')[-1]  # 处理可能的目录结构
                    if base_name == 'CloudflareST.exe' or base_name == 'CloudflareST':
                        with zip_ref.open(name) as src, open(target_path, 'wb') as dst:
                            dst.write(src.read())
                        extracted = True
                        break

        # 清理临时文件
        Path(tmp_path).unlink(missing_ok=True)

        if not extracted:
            logger.error("解压失败：未找到可执行文件")
            return False

        # 设置可执行权限（Unix 系统）
        if system != 'windows':
            import stat
            target_path.chmod(target_path.stat().st_mode | stat.S_IEXEC)

        logger.info(f"CloudflareSpeedTest 已安装到: {target_path}")
        return True

    except requests.RequestException as e:
        logger.error(f"下载失败: {e}")
        return False
    except (tarfile.TarError, zipfile.BadZipFile) as e:
        logger.error(f"解压失败: {e}")
        return False
    except Exception as e:
        logger.error(f"安装失败: {e}")
        return False


def ensure_cfst_tool(config: Config) -> Optional[Path]:
    """
    确保 cfst 工具可用，不存在则自动下载

    Args:
        config: 配置对象

    Returns:
        cfst 工具路径，失败返回 None
    """
    tool_path = get_cfst_tool_path(config.cfst_path)

    if tool_path.exists():
        logger.debug(f"找到 cfst 工具: {tool_path}")
        return tool_path

    logger.info(f"cfst 工具不存在: {tool_path}")

    # 自动下载
    if download_cfst_tool(tool_path):
        return tool_path

    return None


def fetch_top_domains(url: str) -> list[DomainInfo]:
    """
    从 vps789.com 获取 Top 20 域名

    Args:
        url: API 地址

    Returns:
        域名信息列表
    """
    logger.info(f"正在从 {url} 获取域名列表...")

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()

        if data.get('code') != 0:
            raise ValueError(f"API 返回错误: {data.get('message')}")

        domains = []
        for item in data.get('data', {}).get('good', []):
            domain = item.get('ip', '').strip()
            if domain:
                domains.append(DomainInfo(
                    domain=domain,
                    avg_latency=float(item.get('avgLatency', 0)),
                    avg_pkg_lost_rate=float(item.get('avgPkgLostRate', 0)),
                    score=float(item.get('avgScore', 0))
                ))

        logger.info(f"成功获取 {len(domains)} 个域名")
        return domains

    except requests.RequestException as e:
        logger.error(f"获取域名列表失败: {e}")
        raise


def filter_and_resolve_domains(domains: list[DomainInfo], threshold: float,
                                dns_servers: list[str]) -> dict[str, list[str]]:
    """
    筛选丢包率低于阈值的域名，并通过多个 DNS 服务器解析为 IP，合并去重

    Args:
        domains: 域名信息列表
        threshold: 丢包率阈值
        dns_servers: DNS 服务器列表

    Returns:
        IP 到来源域名列表的映射 {ip: [domain1, domain2, ...]}
    """
    # 筛选丢包率低于阈值的域名
    filtered_domains = [d for d in domains if d.avg_pkg_lost_rate < threshold]
    logger.info(f"筛选丢包率 < {threshold}% 的域名: {len(filtered_domains)}/{len(domains)} 个")

    if not filtered_domains:
        logger.warning(f"没有丢包率低于 {threshold}% 的域名，将使用所有域名")
        filtered_domains = domains

    # 解析所有域名的 IP 并去重
    ip_to_domains: dict[str, list[str]] = {}

    logger.info(f"使用 DNS 服务器: {', '.join(dns_servers)}")

    for d in filtered_domains:
        # 通过多个 DNS 服务器解析，获取所有 IP
        ips = resolve_domain_all_ips(d.domain, dns_servers)
        for ip in ips:
            if ip not in ip_to_domains:
                ip_to_domains[ip] = []
            if d.domain not in ip_to_domains[ip]:
                ip_to_domains[ip].append(d.domain)

    logger.info(f"解析得到 {len(ip_to_domains)} 个不重复 IP")

    return ip_to_domains


def resolve_domain_all_ips(domain: str, dns_servers: list[str]) -> list[str]:
    """
    通过多个 DNS 服务器解析域名，获取所有 IP 地址

    Args:
        domain: 域名
        dns_servers: DNS 服务器列表

    Returns:
        去重后的 IP 地址列表
    """
    all_ips: set[str] = set()

    # 1. 首先使用系统默认 DNS 解析（获取所有 A 记录）
    try:
        # 使用 getaddrinfo 获取所有 IP
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        for result in results:
            ip = result[4][0]
            all_ips.add(ip)
            logger.debug(f"系统 DNS 解析 {domain} -> {ip}")
    except socket.gaierror as e:
        logger.debug(f"系统 DNS 解析 {domain} 失败: {e}")

    # 2. 通过指定的 DNS 服务器解析
    for dns_server in dns_servers:
        ips = resolve_with_dns_server(domain, dns_server)
        for ip in ips:
            if ip not in all_ips:
                logger.debug(f"DNS {dns_server} 解析 {domain} -> {ip}")
            all_ips.add(ip)

    if all_ips:
        logger.debug(f"域名 {domain} 共解析到 {len(all_ips)} 个 IP: {', '.join(all_ips)}")
    else:
        logger.warning(f"域名 {domain} 解析失败，未获取到任何 IP")

    return list(all_ips)


def resolve_with_dns_server(domain: str, dns_server: str, timeout: float = 5.0) -> list[str]:
    """
    使用指定的 DNS 服务器解析域名

    Args:
        domain: 域名
        dns_server: DNS 服务器地址
        timeout: 超时时间（秒）

    Returns:
        IP 地址列表
    """
    ips = []

    if HAS_DNSPYTHON:
        # 使用 dnspython 库
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = timeout
            resolver.lifetime = timeout

            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                ips.append(str(rdata))
        except Exception as e:
            logger.debug(f"dnspython 通过 {dns_server} 解析 {domain} 失败: {e}")
    else:
        # 使用 nslookup 命令
        ips = resolve_with_nslookup(domain, dns_server, timeout)

    return ips


def resolve_with_nslookup(domain: str, dns_server: str, timeout: float = 5.0) -> list[str]:
    """
    使用 nslookup 命令解析域名

    Args:
        domain: 域名
        dns_server: DNS 服务器地址
        timeout: 超时时间（秒）

    Returns:
        IP 地址列表
    """
    ips = []
    system = platform.system().lower()

    try:
        if system == 'windows':
            cmd = ['nslookup', domain, dns_server]
        else:
            # Linux/macOS
            cmd = ['nslookup', domain, dns_server]

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = process.stdout

        # 解析 nslookup 输出，提取 IP 地址
        # 跳过 DNS 服务器自身的地址，只提取解析结果
        lines = output.split('\n')
        in_answer_section = False

        for line in lines:
            line = line.strip()
            # 检测到 "Name:" 或 "名称:" 后开始解析
            if 'Name:' in line or '名称:' in line or 'name =' in line.lower():
                in_answer_section = True
                continue

            if in_answer_section:
                # 提取 Address: 或 地址: 后面的 IP
                if 'Address:' in line or '地址:' in line or 'address' in line.lower():
                    # 提取 IPv4 地址
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        # 排除 DNS 服务器自身的地址
                        if ip != dns_server:
                            ips.append(ip)

        # 如果上面的方法没有提取到，尝试直接从输出中提取所有 IPv4 地址
        if not ips:
            # 查找所有 IPv4 地址
            all_ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', output)
            # 排除 DNS 服务器地址和常见的本地地址
            for ip in all_ips:
                if ip != dns_server and not ip.startswith('127.') and ip not in ips:
                    ips.append(ip)

    except subprocess.TimeoutExpired:
        logger.debug(f"nslookup {domain} @{dns_server} 超时")
    except FileNotFoundError:
        logger.debug("找不到 nslookup 命令")
    except Exception as e:
        logger.debug(f"nslookup 解析失败: {e}")

    return ips


def ping_ip(ip: str, count: int = 100, timeout: int = 5) -> PingResult:
    """
    对 IP 进行 ping 测试

    Args:
        ip: 要测试的 IP 地址
        count: ping 次数
        timeout: 超时时间（秒）

    Returns:
        PingResult 对象
    """
    result = PingResult(ip=ip)
    system = platform.system().lower()

    try:
        # 构建 ping 命令
        if system == 'windows':
            cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), ip]
        else:  # Linux/macOS
            cmd = ['ping', '-c', str(count), '-W', str(timeout), ip]

        logger.debug(f"执行命令: {' '.join(cmd)}")

        # 执行 ping
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=count * timeout + 60  # 总超时时间
        )

        output = process.stdout + process.stderr

        # 解析结果
        if system == 'windows':
            result = parse_windows_ping(ip, output, count)
        else:
            result = parse_unix_ping(ip, output, count)

    except subprocess.TimeoutExpired:
        logger.warning(f"Ping {ip} 超时")
    except FileNotFoundError:
        logger.error("找不到 ping 命令")
    except Exception as e:
        logger.error(f"Ping {ip} 出错: {e}")

    return result


def parse_unix_ping(ip: str, output: str, count: int) -> PingResult:
    """解析 Unix/Linux/macOS ping 输出"""
    result = PingResult(ip=ip, packets_sent=count)

    # 解析丢包率
    loss_pattern = r'(\d+)\s+packets?\s+transmitted,\s+(\d+)\s+(?:packets?\s+)?received.*?(\d+(?:\.\d+)?)\s*%\s*packet\s*loss'
    loss_match = re.search(loss_pattern, output, re.IGNORECASE)

    if loss_match:
        result.packets_sent = int(loss_match.group(1))
        result.packets_received = int(loss_match.group(2))
        result.packet_loss = float(loss_match.group(3))
        result.success = result.packets_received > 0

    # 解析延迟
    latency_pattern = r'(?:round-trip|rtt)\s+min/avg/max/(?:stddev|mdev)\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)'
    latency_match = re.search(latency_pattern, output, re.IGNORECASE)

    if latency_match:
        result.min_latency = float(latency_match.group(1))
        result.avg_latency = float(latency_match.group(2))
        result.max_latency = float(latency_match.group(3))

    return result


def parse_windows_ping(ip: str, output: str, count: int) -> PingResult:
    """解析 Windows ping 输出"""
    result = PingResult(ip=ip, packets_sent=count)

    # 解析丢包率
    loss_pattern = r'Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)\s*\((\d+(?:\.\d+)?)\s*%\s*loss\)'
    loss_match = re.search(loss_pattern, output, re.IGNORECASE)

    if loss_match:
        result.packets_sent = int(loss_match.group(1))
        result.packets_received = int(loss_match.group(2))
        result.packet_loss = float(loss_match.group(4))
        result.success = result.packets_received > 0

    # 解析延迟
    latency_pattern = r'Minimum\s*=\s*(\d+)\s*ms,\s*Maximum\s*=\s*(\d+)\s*ms,\s*Average\s*=\s*(\d+)\s*ms'
    latency_match = re.search(latency_pattern, output, re.IGNORECASE)

    if latency_match:
        result.min_latency = float(latency_match.group(1))
        result.max_latency = float(latency_match.group(2))
        result.avg_latency = float(latency_match.group(3))

    return result


def test_all_ips(ip_to_domains: dict[str, list[str]], ping_count: int = 100,
                 max_workers: int = 5) -> list[PingResult]:
    """
    对所有 IP 进行并发 ping 测试

    Args:
        ip_to_domains: IP 到来源域名的映射
        ping_count: 每个 IP 的 ping 次数
        max_workers: 并发数

    Returns:
        测试结果列表
    """
    ips = list(ip_to_domains.keys())
    logger.info(f"开始测试 {len(ips)} 个 IP，每个 ping {ping_count} 次...")
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(ping_ip, ip, ping_count): ip
            for ip in ips
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                result.source_domains = ip_to_domains.get(ip, [])
                results.append(result)
                if result.success:
                    logger.info(f"✓ {ip}: 丢包率={result.packet_loss:.1f}%, "
                               f"平均延迟={result.avg_latency:.1f}ms")
                else:
                    logger.warning(f"✗ {ip}: 测试失败")
            except Exception as e:
                logger.error(f"✗ {ip}: {e}")
                results.append(PingResult(ip=ip, source_domains=ip_to_domains.get(ip, [])))

    return results


def run_speed_test(ips: list[str], config: Config, cfst_path: Path) -> list[SpeedTestResult]:
    """
    使用 cfst 工具进行速度测试

    Args:
        ips: 要测试的 IP 列表
        config: 配置对象
        cfst_path: cfst 工具路径

    Returns:
        速度测试结果列表，按下载速度降序排列
    """
    import csv
    import tempfile

    if not ips:
        return []

    logger.info(f"\n开始速度测试，共 {len(ips)} 个 IP...")
    logger.info(f"测速地址: {config.cfst_url}")

    # 创建临时结果文件
    result_file = SCRIPT_DIR / 'cfst_result.csv'

    # 构建 cfst 命令
    # -ip: 指定 IP 列表
    # -url: 测速地址
    # -o: 输出文件
    # -dn: 测速数量（与 IP 数量相同）
    # -dt: 测速时间
    # -tp: 测速端口
    # -p: 显示结果数量
    ip_list = ','.join(ips)
    cmd = [
        str(cfst_path),
        '-ip', ip_list,
        '-url', config.cfst_url,
        '-o', str(result_file),
        '-dn', str(len(ips)),  # 测试所有 IP
        '-dt', str(config.cfst_timeout),
        '-tp', str(config.cfst_port),
        '-p', str(len(ips)),  # 显示所有结果
    ]

    logger.debug(f"执行命令: {' '.join(cmd)}")

    try:
        # 执行 cfst
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.cfst_timeout * len(ips) + 60,  # 总超时时间
            cwd=str(SCRIPT_DIR)  # 在脚本目录下执行
        )

        # 输出 cfst 的运行信息
        if process.stdout:
            for line in process.stdout.strip().split('\n'):
                if line.strip():
                    logger.info(f"[cfst] {line}")

        if process.returncode != 0 and process.stderr:
            logger.warning(f"cfst 警告: {process.stderr}")

    except subprocess.TimeoutExpired:
        logger.error("速度测试超时")
        return []
    except Exception as e:
        logger.error(f"速度测试失败: {e}")
        return []

    # 解析结果文件
    results = []
    if result_file.exists():
        try:
            with open(result_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                header = next(reader, None)  # 跳过标题行

                if header:
                    # 查找列索引
                    # 标题通常是: IP 地址,已发送,已接收,丢包率,平均延迟,下载速度 (MB/s)
                    ip_idx = 0
                    speed_idx = -1
                    latency_idx = -1

                    for i, col in enumerate(header):
                        if '下载速度' in col or 'speed' in col.lower():
                            speed_idx = i
                        if '延迟' in col or 'latency' in col.lower():
                            latency_idx = i

                    for row in reader:
                        if len(row) > max(ip_idx, speed_idx, latency_idx):
                            try:
                                ip = row[ip_idx].strip()
                                speed = float(row[speed_idx].strip()) if speed_idx >= 0 and row[speed_idx].strip() else 0.0
                                latency = float(row[latency_idx].strip()) if latency_idx >= 0 and row[latency_idx].strip() else float('inf')

                                results.append(SpeedTestResult(
                                    ip=ip,
                                    download_speed=speed,
                                    avg_latency=latency,
                                    success=speed > 0
                                ))
                            except (ValueError, IndexError) as e:
                                logger.debug(f"解析行失败: {row}, 错误: {e}")

            # 清理结果文件
            result_file.unlink(missing_ok=True)

        except Exception as e:
            logger.error(f"解析速度测试结果失败: {e}")

    # 按下载速度降序排序
    results.sort(key=lambda x: x.download_speed, reverse=True)

    # 输出结果摘要
    if results:
        logger.info(f"\n速度测试完成，有效结果: {len([r for r in results if r.success])}/{len(results)}")
        for i, r in enumerate(results[:5], 1):
            if r.success:
                logger.info(f"  {i}. {r.ip}: {r.download_speed:.2f} MB/s, 延迟 {r.avg_latency:.1f}ms")
    else:
        logger.warning("速度测试未获得任何有效结果")

    return results


def select_best_ip(results: list[PingResult]) -> Optional[PingResult]:
    """
    选择最佳的 IP
    优先考虑丢包率，其次考虑平均延迟

    Args:
        results: ping 测试结果列表

    Returns:
        最佳 IP 的测试结果，如果没有可用 IP 返回 None
    """
    # 过滤成功的结果
    valid_results = [r for r in results if r.success]

    if not valid_results:
        logger.error("没有可用的 IP")
        return None

    # 按丢包率和延迟排序
    sorted_results = sorted(
        valid_results,
        key=lambda x: (x.packet_loss, x.avg_latency)
    )

    best = sorted_results[0]

    # 输出结果
    logger.info(f"\n{'='*60}")
    logger.info(f"最佳 IP: {best.ip}")
    domains_str = ', '.join(best.source_domains[:3])
    if len(best.source_domains) > 3:
        domains_str += f" 等 {len(best.source_domains)} 个域名"
    logger.info(f"  来源: {domains_str}")
    logger.info(f"  丢包率: {best.packet_loss:.1f}%")
    logger.info(f"  平均延迟: {best.avg_latency:.1f}ms")
    logger.info(f"  最小延迟: {best.min_latency:.1f}ms")
    logger.info(f"  最大延迟: {best.max_latency:.1f}ms")
    logger.info(f"{'='*60}")

    return best


def update_he_dns(hostname: str, password: str, ip: str) -> bool:
    """
    更新 dns.he.net 的 A 记录

    Args:
        hostname: 要更新的主机名（如 dyn.example.com）
        password: 动态 DNS 密钥
        ip: 新的 IP 地址

    Returns:
        是否更新成功
    """
    url = "https://dyn.dns.he.net/nic/update"

    params = {
        'hostname': hostname,
        'password': password,
        'myip': ip
    }

    logger.info(f"正在更新 A 记录: {hostname} -> {ip}...")

    try:
        response = requests.get(url, params=params, timeout=30)
        result = response.text.strip()

        # 检查响应
        # 成功响应: "good 192.168.0.1" 或 "nochg 192.168.0.1"
        if result.startswith('good') or result.startswith('nochg'):
            logger.info(f"✓ 更新成功: {result}")
            return True
        else:
            logger.error(f"✗ 更新失败: {result}")
            return False

    except requests.RequestException as e:
        logger.error(f"✗ 请求失败: {e}")
        return False


def main() -> int:
    """主函数"""
    print("=" * 60)
    print("  HE.net DNS A 记录自动更新工具")
    print("  选择最佳 Cloudflare 优化 IP 并自动更新")
    print("=" * 60)
    print()

    # 1. 加载配置
    config = load_config()
    if not config:
        return 1

    # 设置日志级别
    if config.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("调试模式已启用")

    logger.info(f"目标主机名: {config.hostname}")
    logger.info(f"丢包率筛选阈值: {config.pkg_lost_threshold}%")
    logger.info(f"DNS 服务器: {', '.join(config.dns_servers)}")

    # 检查速度测试配置
    if not config.cfst_url:
        logger.error("配置文件缺少必填项: CFST_URL 未填写")
        logger.error("CFST_URL 是进行速度测试所必需的测速地址")
        logger.error(f"请编辑配置文件: {ENV_FILE}")
        return 1

    logger.info(f"速度测试地址: {config.cfst_url}")
    logger.info(f"速度测试 IP 数量: 前 {config.cfst_top_count} 个")

    try:
        # 2. 检查/下载 cfst 工具
        cfst_path = ensure_cfst_tool(config)
        if not cfst_path:
            logger.error("cfst 工具不可用，无法进行速度测试")
            return 1

        # 3. 获取域名列表
        domains = fetch_top_domains(config.api_url)

        if not domains:
            logger.error("未获取到任何域名")
            return 1

        # 4. 筛选域名并解析 IP（使用多个 DNS 服务器）
        ip_to_domains = filter_and_resolve_domains(
            domains, config.pkg_lost_threshold, config.dns_servers
        )

        if not ip_to_domains:
            logger.error("没有可解析的 IP")
            return 1

        # 5. 选择最佳 IP
        best_ip = None
        best_speed = 0.0
        source_domains = []

        if config.skip_ping:
            # 跳过 ping 测试，直接使用前 N 个 IP 进行速度测试
            logger.info("跳过本地 ping 测试，直接使用解析到的 IP 进行速度测试...")
            top_ips = list(ip_to_domains.keys())[:config.cfst_top_count]
        else:
            # 对所有 IP 进行 ping 测试
            results = test_all_ips(ip_to_domains, config.ping_count, config.ping_workers)

            # 过滤成功的结果并按丢包率和延迟排序
            valid_results = [r for r in results if r.success]
            if not valid_results:
                logger.error("没有可用的 IP（所有 IP ping 测试失败）")
                return 1

            sorted_results = sorted(
                valid_results,
                key=lambda x: (x.packet_loss, x.avg_latency)
            )

            # 选取前 N 个 IP 进入速度测试
            top_count = min(config.cfst_top_count, len(sorted_results))
            top_results = sorted_results[:top_count]
            top_ips = [r.ip for r in top_results]

            logger.info(f"\n从 ping 测试结果中选取前 {len(top_ips)} 个 IP 进行速度测试:")
            for i, r in enumerate(top_results, 1):
                logger.info(f"  {i}. {r.ip}: 丢包率={r.packet_loss:.1f}%, 延迟={r.avg_latency:.1f}ms")

        # 6. 进行速度测试
        speed_results = run_speed_test(top_ips, config, cfst_path)

        if speed_results and speed_results[0].success:
            # 选择速度最快的 IP
            best = speed_results[0]
            best_ip = best.ip
            best_speed = best.download_speed
            source_domains = ip_to_domains.get(best_ip, [])

            logger.info(f"\n{'='*60}")
            logger.info(f"最佳 IP（速度最快）: {best_ip}")
            domains_str = ', '.join(source_domains[:3])
            if len(source_domains) > 3:
                domains_str += f" 等 {len(source_domains)} 个域名"
            logger.info(f"  来源: {domains_str}")
            logger.info(f"  下载速度: {best_speed:.2f} MB/s")
            logger.info(f"  平均延迟: {best.avg_latency:.1f}ms")
            logger.info(f"{'='*60}")
        else:
            # 速度测试失败，回退到使用 ping 结果
            logger.warning("速度测试未获得有效结果，将使用 ping 测试最佳 IP")
            if top_ips:
                best_ip = top_ips[0]
                source_domains = ip_to_domains.get(best_ip, [])
                logger.info(f"回退使用 IP: {best_ip}")

        if not best_ip:
            logger.error("没有可用的 IP")
            return 1

        # 7. 更新 DNS 记录
        logger.info("")
        success = update_he_dns(config.hostname, config.password, best_ip)

        # 8. 输出结果
        print()
        print("=" * 60)
        if success:
            print("  更新完成！")
            print()
            print(f"  {config.hostname} -> {best_ip}")
            source = source_domains[0] if source_domains else "未知"
            print(f"  来源: {source}")
            if best_speed > 0:
                print(f"  下载速度: {best_speed:.2f} MB/s")
        else:
            print("  更新失败！")
            print("  请检查主机名和密钥是否正确")
        print("=" * 60)

        return 0 if success else 1

    except KeyboardInterrupt:
        logger.info("\n用户中断")
        return 130
    except Exception as e:
        logger.error(f"发生错误: {e}")
        if config.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
