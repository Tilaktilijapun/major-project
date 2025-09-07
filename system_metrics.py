import psutil
import platform
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S %Z'
)

def get_cpu_usage(interval: float = 0.1) -> float:
    """Return overall CPU usage percentage with optional interval."""
    try:
        return psutil.cpu_percent(interval=interval)
    except Exception as e:
        logging.error(f"Error in get_cpu_usage: {e}")
        return 0.0

def get_cpu_usage_per_core(interval: float = 0.1) -> list:
    """Return CPU usage percentage for each core."""
    try:
        return psutil.cpu_percent(interval=interval, percpu=True)
    except Exception as e:
        logging.error(f"Error in get_cpu_usage_per_core: {e}")
        return []

def get_memory_usage():
    """Return memory usage in percentage."""
    try:
        memory = psutil.virtual_memory()
        return memory.percent
    except Exception as e:
        logging.error(f"Error in get_memory_usage: {e}")
        return 0.0

def get_disk_usage(path: str = "/") -> float:
    """Returns disk usage percentage for a given path."""
    try:
        return psutil.disk_usage(path).percent
    except Exception as e:
        logging.error(f"Error in get_disk_usage: {e}")
        return 0.0

def get_network_stats():
    """Return sent/received network bytes."""
    try:
        net_io = psutil.net_io_counters()
        return {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv
        }
    except Exception as e:
        logging.error(f"Error in get_network_stats: {e}")
        return {"bytes_sent": 0, "bytes_recv": 0}

def get_system_temperature():
    """Return system temperature in Celsius (if available)."""
    try:
        if not hasattr(psutil, "sensors_temperatures"):
            return 45.0  # fallback if function not supported
        temps = psutil.sensors_temperatures()
        if not temps:
            return 45.0
        for name, entries in temps.items():
            if entries:
                return entries[0].current
        return 45.0
    except Exception as e:
        logging.error(f"Error in get_system_temperature: {e}")
        return 45.0

def get_system_info():
    """Return basic system information."""
    try:
        return {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "cpu_count": psutil.cpu_count(logical=True),
            "total_memory_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2)
        }
    except Exception as e:
        logging.error(f"Error in get_system_info: {e}")
        return {
            "platform": "Unknown",
            "platform_version": "Unknown",
            "architecture": "Unknown",
            "cpu_count": 0,
            "total_memory_gb": 0.0
        }

def get_network_io():
    """Return network I/O stats for all interfaces."""
    try:
        io = psutil.net_io_counters(pernic=True)
        return {iface: {
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv
        } for iface, stats in io.items()}
    except Exception as e:
        logging.error(f"Error in get_network_io: {e}")
        return {}

def get_cpu_times():
    """Return CPU times."""
    try:
        times = psutil.cpu_times()
        return {
            "user": times.user,
            "system": times.system,
            "idle": times.idle
        }
    except Exception as e:
        logging.error(f"Error in get_cpu_times: {e}")
        return {"user": 0, "system": 0, "idle": 0}

def get_memory_info():
    """Return detailed memory information."""
    try:
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return {
            "virtual_memory": {
                "total": mem.total,
                "used": mem.used,
                "free": mem.available,
                "percent": mem.percent
            },
            "swap_memory": {
                "total": swap.total,
                "used": swap.used,
                "free": swap.free,
                "percent": swap.percent
            }
        }
    except Exception as e:
        logging.error(f"Error in get_memory_info: {e}")
        return {
            "virtual_memory": {"total": 0, "used": 0, "free": 0, "percent": 0.0},
            "swap_memory": {"total": 0, "used": 0, "free": 0, "percent": 0.0}
        }

def get_disk_io_info():
    """Return disk I/O stats for all disks."""
    try:
        io = psutil.disk_io_counters(perdisk=True)
        return {disk: {
            "read_count": stats.read_count,
            "write_count": stats.write_count,
            "read_bytes": stats.read_bytes,
            "write_bytes": stats.write_bytes
        } for disk, stats in io.items()}
    except Exception as e:
        logging.error(f"Error in get_disk_io_info: {e}")
        return {}

def get_network_details():
    """Return detailed network interface information."""
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        return {iface: {
            "addresses": [{
                "family": str(addr.family),  # Convert enum to string
                "address": addr.address,
                "netmask": addr.netmask,
                "broadcast": addr.broadcast if addr.broadcast else None
            } for addr in addrs_list],
            "is_up": stats.get(iface, psutil.net_if_addrs(stats=None)).isup,
            "speed_mbps": stats.get(iface, psutil.net_if_addrs(stats=None)).speed
        } for iface, addrs_list in addrs.items()}
    except Exception as e:
        logging.error(f"Error in get_network_details: {e}")
        return {}