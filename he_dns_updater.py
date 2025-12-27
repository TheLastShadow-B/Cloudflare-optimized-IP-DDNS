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
import requests
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

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

# [可选] 是否跳过本地 ping 测试，直接使用 API 数据（true/false，默认: false）
SKIP_PING=false

# [可选] 是否启用调试模式（true/false，默认: false）
DEBUG=false
"""

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 默认丢包率筛选阈值
DEFAULT_PKG_LOST_THRESHOLD = 0.5


@dataclass
class Config:
    """配置类"""
    hostname: str
    password: str
    ping_count: int = 100
    ping_workers: int = 5
    api_url: str = "https://vps789.com/public/sum/cfIpTop20"
    pkg_lost_threshold: float = DEFAULT_PKG_LOST_THRESHOLD
    skip_ping: bool = False
    debug: bool = False


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

    config = Config(
        hostname=hostname,
        password=password,
        ping_count=parse_int(env_vars.get('PING_COUNT', ''), 100),
        ping_workers=parse_int(env_vars.get('PING_WORKERS', ''), 5),
        api_url=env_vars.get('API_URL', '').strip() or "https://vps789.com/public/sum/cfIpTop20",
        pkg_lost_threshold=parse_float(env_vars.get('PKG_LOST_THRESHOLD', ''), DEFAULT_PKG_LOST_THRESHOLD),
        skip_ping=parse_bool(env_vars.get('SKIP_PING', ''), False),
        debug=parse_bool(env_vars.get('DEBUG', ''), False),
    )

    return config


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


def filter_and_resolve_domains(domains: list[DomainInfo], threshold: float) -> dict[str, list[str]]:
    """
    筛选丢包率低于阈值的域名，并解析为 IP，合并去重

    Args:
        domains: 域名信息列表
        threshold: 丢包率阈值

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

    for d in filtered_domains:
        ip = resolve_domain(d.domain)
        if ip:
            if ip not in ip_to_domains:
                ip_to_domains[ip] = []
            ip_to_domains[ip].append(d.domain)

    logger.info(f"解析得到 {len(ip_to_domains)} 个不重复 IP")

    return ip_to_domains


def resolve_domain(domain: str) -> Optional[str]:
    """
    解析域名获取 IP 地址

    Args:
        domain: 域名

    Returns:
        IP 地址，解析失败返回 None
    """
    try:
        ip = socket.gethostbyname(domain)
        logger.debug(f"域名 {domain} 解析为 IP: {ip}")
        return ip
    except socket.gaierror as e:
        logger.debug(f"解析域名 {domain} 失败: {e}")
        return None


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

    try:
        # 2. 获取域名列表
        domains = fetch_top_domains(config.api_url)

        if not domains:
            logger.error("未获取到任何域名")
            return 1

        # 3. 筛选域名并解析 IP
        ip_to_domains = filter_and_resolve_domains(domains, config.pkg_lost_threshold)

        if not ip_to_domains:
            logger.error("没有可解析的 IP")
            return 1

        # 4. 选择最佳 IP
        if config.skip_ping:
            # 跳过 ping 测试，直接使用第一个 IP
            logger.info("跳过本地 ping 测试，直接使用解析到的第一个 IP...")

            first_ip = list(ip_to_domains.keys())[0]
            best_result = PingResult(
                ip=first_ip,
                source_domains=ip_to_domains[first_ip],
                success=True
            )

            logger.info(f"\n{'='*60}")
            logger.info(f"选择 IP: {best_result.ip}")
            logger.info(f"  来源: {', '.join(best_result.source_domains[:3])}")
            logger.info(f"{'='*60}")
        else:
            # 对所有 IP 进行 ping 测试
            results = test_all_ips(ip_to_domains, config.ping_count, config.ping_workers)
            best_result = select_best_ip(results)

        if not best_result:
            logger.error("没有可用的 IP")
            return 1

        # 5. 更新 DNS 记录
        logger.info("")
        success = update_he_dns(config.hostname, config.password, best_result.ip)

        # 6. 输出结果
        print()
        print("=" * 60)
        if success:
            print("  更新完成！")
            print()
            print(f"  {config.hostname} -> {best_result.ip}")
            source = best_result.source_domains[0] if best_result.source_domains else "未知"
            print(f"  来源: {source}")
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
