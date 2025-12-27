#!/usr/bin/env python3
"""
HE.net DNS A 记录自动更新工具（负载均衡版）

从 vps789.com 获取 Cloudflare 优化 IP 的 Top 20 域名，
进行 ping 测试后选择最佳的 3 个域名，解析为 IP 后更新 dns.he.net 的 3 个 A 记录。
多个 A 记录实现 DNS 轮询负载均衡。

注意：dns.he.net 不支持通过 API 删除/创建记录，只能更新已有的动态 A 记录。
请先在 dns.he.net 控制面板创建 3 个相同主机名的 A 记录并启用动态 DNS，获取各自的密钥。

配置文件: .env（与脚本同目录）
运行方式: python he_dns_updater.py（无需任何参数）

作者: Claude Code
日期: 2025-12-27
"""

import os
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
ENV_TEMPLATE = """# HE.net DNS 自动更新工具配置文件（负载均衡版）
# 请填写以下配置项后保存
#
# 使用说明：
# 1. 在 dns.he.net 控制面板为同一个主机名创建 3 个 A 记录
# 2. 分别启用动态 DNS 并生成密钥
# 3. 将主机名和 3 个密钥填写到下面的配置中

# [必填] dns.he.net 上要更新的主机名（如: cdn.example.com）
# 注意：3 个 A 记录使用相同的主机名
HE_HOSTNAME=

# [必填] 3 个动态 DNS 密钥（在 dns.he.net 控制面板为每个 A 记录分别生成）
# 用英文逗号分隔，例如: key1,key2,key3
HE_PASSWORDS=

# [可选] 每个域名的 ping 次数（默认: 100）
PING_COUNT=100

# [可选] 并发测试线程数（默认: 5）
PING_WORKERS=5

# [可选] 获取域名列表的 API 地址（默认使用 vps789.com）
API_URL=https://vps789.com/public/sum/cfIpTop20

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

# 负载均衡 A 记录数量
NUM_RECORDS = 3


@dataclass
class Config:
    """配置类"""
    hostname: str
    passwords: list[str] = field(default_factory=list)
    ping_count: int = 100
    ping_workers: int = 5
    api_url: str = "https://vps789.com/public/sum/cfIpTop20"
    skip_ping: bool = False
    debug: bool = False


@dataclass
class PingResult:
    """Ping 测试结果"""
    domain: str
    packets_sent: int = 0
    packets_received: int = 0
    packet_loss: float = 100.0
    min_latency: float = float('inf')
    avg_latency: float = float('inf')
    max_latency: float = float('inf')
    success: bool = False
    resolved_ip: Optional[str] = None


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
    passwords_str = env_vars.get('HE_PASSWORDS', '').strip()

    # 解析密钥列表
    passwords = [p.strip() for p in passwords_str.split(',') if p.strip()]

    if not hostname:
        logger.error("配置文件缺少必填项: HE_HOSTNAME 未填写")
        logger.error(f"请编辑配置文件: {ENV_FILE}")
        return None

    if len(passwords) < NUM_RECORDS:
        logger.error(f"配置文件缺少必填项: HE_PASSWORDS 需要 {NUM_RECORDS} 个密钥")
        logger.error(f"当前配置了 {len(passwords)} 个密钥，需要 {NUM_RECORDS} 个")
        logger.error("请在 dns.he.net 为同一主机名创建 3 个 A 记录并获取密钥")
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

    config = Config(
        hostname=hostname,
        passwords=passwords[:NUM_RECORDS],  # 只取前 3 个
        ping_count=parse_int(env_vars.get('PING_COUNT', ''), 100),
        ping_workers=parse_int(env_vars.get('PING_WORKERS', ''), 5),
        api_url=env_vars.get('API_URL', '').strip() or "https://vps789.com/public/sum/cfIpTop20",
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


def ping_domain(domain: str, count: int = 100, timeout: int = 5) -> PingResult:
    """
    对域名进行 ping 测试

    Args:
        domain: 要测试的域名
        count: ping 次数
        timeout: 超时时间（秒）

    Returns:
        PingResult 对象
    """
    result = PingResult(domain=domain)
    system = platform.system().lower()

    try:
        # 构建 ping 命令
        if system == 'windows':
            cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), domain]
        else:  # Linux/macOS
            cmd = ['ping', '-c', str(count), '-W', str(timeout), domain]

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
            result = parse_windows_ping(domain, output, count)
        else:
            result = parse_unix_ping(domain, output, count)

    except subprocess.TimeoutExpired:
        logger.warning(f"Ping {domain} 超时")
    except FileNotFoundError:
        logger.error("找不到 ping 命令")
    except Exception as e:
        logger.error(f"Ping {domain} 出错: {e}")

    return result


def parse_unix_ping(domain: str, output: str, count: int) -> PingResult:
    """解析 Unix/Linux/macOS ping 输出"""
    result = PingResult(domain=domain, packets_sent=count)

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


def parse_windows_ping(domain: str, output: str, count: int) -> PingResult:
    """解析 Windows ping 输出"""
    result = PingResult(domain=domain, packets_sent=count)

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


def test_all_domains(domains: list[DomainInfo], ping_count: int = 100,
                     max_workers: int = 5) -> list[PingResult]:
    """
    对所有域名进行并发 ping 测试

    Args:
        domains: 域名列表
        ping_count: 每个域名的 ping 次数
        max_workers: 并发数

    Returns:
        测试结果列表
    """
    logger.info(f"开始测试 {len(domains)} 个域名，每个 ping {ping_count} 次...")
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(ping_domain, d.domain, ping_count): d.domain
            for d in domains
        }

        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                results.append(result)
                if result.success:
                    logger.info(f"✓ {domain}: 丢包率={result.packet_loss:.1f}%, "
                               f"平均延迟={result.avg_latency:.1f}ms")
                else:
                    logger.warning(f"✗ {domain}: 测试失败")
            except Exception as e:
                logger.error(f"✗ {domain}: {e}")
                results.append(PingResult(domain=domain))

    return results


def select_best_domains(results: list[PingResult], count: int = NUM_RECORDS) -> list[PingResult]:
    """
    选择最佳的多个域名
    优先考虑丢包率，其次考虑平均延迟

    Args:
        results: ping 测试结果列表
        count: 需要选择的域名数量

    Returns:
        最佳域名的测试结果列表
    """
    # 过滤成功的结果
    valid_results = [r for r in results if r.success]

    if not valid_results:
        logger.error("没有可用的域名")
        return []

    # 按丢包率和延迟排序
    sorted_results = sorted(
        valid_results,
        key=lambda x: (x.packet_loss, x.avg_latency)
    )

    # 取前 count 个，并确保 IP 不重复
    best_results = []
    seen_ips = set()

    for result in sorted_results:
        # 解析域名获取 IP
        ip = resolve_domain(result.domain)
        if ip and ip not in seen_ips:
            result.resolved_ip = ip
            best_results.append(result)
            seen_ips.add(ip)

            if len(best_results) >= count:
                break

    if len(best_results) < count:
        logger.warning(f"只找到 {len(best_results)} 个不重复 IP 的可用域名（需要 {count} 个）")

    # 输出结果
    logger.info(f"\n{'='*60}")
    logger.info(f"已选择最佳的 {len(best_results)} 个域名（用于负载均衡）:")
    for i, r in enumerate(best_results, 1):
        logger.info(f"  [{i}] {r.domain}")
        logger.info(f"      IP: {r.resolved_ip}")
        logger.info(f"      丢包率: {r.packet_loss:.1f}%, 平均延迟: {r.avg_latency:.1f}ms")
    logger.info(f"{'='*60}")

    return best_results


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
        logger.error(f"解析域名 {domain} 失败: {e}")
        return None


def update_he_dns(hostname: str, password: str, ip: str, record_index: int) -> bool:
    """
    更新 dns.he.net 的 A 记录

    Args:
        hostname: 要更新的主机名（如 dyn.example.com）
        password: 动态 DNS 密钥
        ip: 新的 IP 地址
        record_index: 记录索引（用于日志显示）

    Returns:
        是否更新成功
    """
    url = "https://dyn.dns.he.net/nic/update"

    params = {
        'hostname': hostname,
        'password': password,
        'myip': ip
    }

    logger.info(f"正在更新 A 记录 [{record_index}]: {hostname} -> {ip}...")

    try:
        response = requests.get(url, params=params, timeout=30)
        result = response.text.strip()

        # 检查响应
        # 成功响应: "good 192.168.0.1" 或 "nochg 192.168.0.1"
        if result.startswith('good') or result.startswith('nochg'):
            logger.info(f"  ✓ 记录 [{record_index}] 更新成功: {result}")
            return True
        else:
            logger.error(f"  ✗ 记录 [{record_index}] 更新失败: {result}")
            return False

    except requests.RequestException as e:
        logger.error(f"  ✗ 记录 [{record_index}] 请求失败: {e}")
        return False


def update_all_records(hostname: str, passwords: list[str], ips: list[str]) -> tuple[int, int]:
    """
    更新所有 A 记录

    Args:
        hostname: 主机名
        passwords: 密钥列表
        ips: IP 地址列表

    Returns:
        (成功数, 失败数)
    """
    success_count = 0
    fail_count = 0

    for i, (password, ip) in enumerate(zip(passwords, ips), 1):
        if update_he_dns(hostname, password, ip, i):
            success_count += 1
        else:
            fail_count += 1

    return success_count, fail_count


def main() -> int:
    """主函数"""
    print("=" * 60)
    print("  HE.net DNS A 记录自动更新工具（负载均衡版）")
    print(f"  选择最佳 {NUM_RECORDS} 个 Cloudflare 优化 IP 并自动更新")
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
    logger.info(f"配置的密钥数量: {len(config.passwords)}")

    try:
        # 2. 获取域名列表
        domains = fetch_top_domains(config.api_url)

        if not domains:
            logger.error("未获取到任何域名")
            return 1

        # 3. 选择最佳域名
        if config.skip_ping:
            # 使用 API 数据选择
            logger.info("使用 API 返回的数据选择最佳域名（跳过本地 ping 测试）...")
            sorted_domains = sorted(
                domains,
                key=lambda x: (x.avg_pkg_lost_rate, x.avg_latency)
            )

            # 解析并去重
            best_results = []
            seen_ips = set()

            for d in sorted_domains:
                ip = resolve_domain(d.domain)
                if ip and ip not in seen_ips:
                    result = PingResult(
                        domain=d.domain,
                        packet_loss=d.avg_pkg_lost_rate,
                        avg_latency=d.avg_latency,
                        success=True,
                        resolved_ip=ip
                    )
                    best_results.append(result)
                    seen_ips.add(ip)

                    if len(best_results) >= NUM_RECORDS:
                        break

            logger.info(f"\n{'='*60}")
            logger.info(f"已选择最佳的 {len(best_results)} 个域名（基于 API 数据）:")
            for i, r in enumerate(best_results, 1):
                logger.info(f"  [{i}] {r.domain}")
                logger.info(f"      IP: {r.resolved_ip}")
                logger.info(f"      丢包率: {r.packet_loss:.2f}%, 平均延迟: {r.avg_latency:.1f}ms")
            logger.info(f"{'='*60}")
        else:
            # 进行本地 ping 测试
            results = test_all_domains(domains, config.ping_count, config.ping_workers)
            best_results = select_best_domains(results, NUM_RECORDS)

        if not best_results:
            logger.error("没有可用的域名")
            return 1

        # 4. 提取 IP 地址
        ips = [r.resolved_ip for r in best_results if r.resolved_ip]

        if len(ips) < NUM_RECORDS:
            logger.warning(f"只有 {len(ips)} 个可用 IP，将只更新这些记录")

        # 5. 更新 DNS 记录
        logger.info(f"\n开始更新 {len(ips)} 个 A 记录...")
        success_count, fail_count = update_all_records(
            config.hostname,
            config.passwords[:len(ips)],
            ips
        )

        # 6. 输出结果
        print()
        print("=" * 60)
        print("  更新完成！")
        print(f"  成功: {success_count}, 失败: {fail_count}")
        print()
        print(f"  {config.hostname} 现在解析到以下 IP（轮询负载均衡）:")
        for i, result in enumerate(best_results[:len(ips)], 1):
            print(f"    [{i}] {result.resolved_ip} (来源: {result.domain})")
        print("=" * 60)

        return 0 if fail_count == 0 else 1

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
