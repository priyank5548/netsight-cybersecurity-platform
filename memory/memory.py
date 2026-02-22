import psutil
import platform
import time
from statistics import mean
import argparse
import re
from datetime import datetime



# ==========================================================
# Utility Functions
# ==========================================================

def bytes_to_gb(value):
    return round(value / (1024 ** 3), 2)


def print_section(title):
    print("\n" + "=" * 50)
    print(f"{title.center(50)}")
    print("=" * 50)


# ==========================================================
# RAM DETAILS
# ==========================================================

def get_ram_details():
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()

    return {
        "total": bytes_to_gb(vm.total),
        "available": bytes_to_gb(vm.available),
        "used": bytes_to_gb(vm.used),
        "free": bytes_to_gb(vm.free),
        "percent": vm.percent,
        "swap_total": bytes_to_gb(swap.total),
        "swap_used": bytes_to_gb(swap.used),
        "swap_free": bytes_to_gb(swap.free),
        "swap_percent": swap.percent
    }



def show_system_summary():
    print_section("SYSTEM SUMMARY")

    print(f"{'OS':<25}: {platform.system()} {platform.release()}")
    print(f"{'Architecture':<25}: {platform.architecture()[0]}")
    print(f"{'CPU Cores (Logical)':<25}: {psutil.cpu_count(logical=True)}")
    print(f"{'CPU Cores (Physical)':<25}: {psutil.cpu_count(logical=False)}")
    print(f"{'Total RAM':<25}: {round(psutil.virtual_memory().total / (1024**3), 2)} GB")
    print(f"{'System Uptime':<25}: {round(time.time() - psutil.boot_time()) // 3600} hours")



def show_advanced_ram():
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()

    print_section("ADVANCED MEMORY BREAKDOWN")

    print(f"{'Total':<25}: {bytes_to_gb(vm.total)} GB")
    print(f"{'Available':<25}: {bytes_to_gb(vm.available)} GB")
    print(f"{'Used':<25}: {bytes_to_gb(vm.used)} GB")
    print(f"{'Free':<25}: {bytes_to_gb(vm.free)} GB")
    print(f"{'Active':<25}: {bytes_to_gb(getattr(vm, 'active', 0))} GB")
    print(f"{'Inactive':<25}: {bytes_to_gb(getattr(vm, 'inactive', 0))} GB")
    print(f"{'Buffers':<25}: {bytes_to_gb(getattr(vm, 'buffers', 0))} GB")
    print(f"{'Cached':<25}: {bytes_to_gb(getattr(vm, 'cached', 0))} GB")
    print(f"{'Shared':<25}: {bytes_to_gb(getattr(vm, 'shared', 0))} GB")

    print("\nSwap / Pagefile Info")
    print(f"{'Swap Total':<25}: {bytes_to_gb(swap.total)} GB")
    print(f"{'Swap Used':<25}: {bytes_to_gb(swap.used)} GB")
    print(f"{'Swap Free':<25}: {bytes_to_gb(swap.free)} GB")



def memory_pressure_status():
    percent = psutil.virtual_memory().percent

    if percent < 60:
        return "HEALTHY"
    elif percent < 80:
        return "MODERATE"
    else:
        return "HIGH PRESSURE"



def memory_health_analysis():
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()

    print_section("MEMORY HEALTH ANALYSIS")

    print(f"Current Usage: {vm.percent}%")
    print(f"Swap Usage   : {swap.percent}%")
    print(f"Pressure     : {memory_pressure_status()}")

    if vm.percent > 80:
        print("⚠ High RAM usage detected.")
    if swap.percent > 20:
        print("⚠ Swap usage rising — possible memory stress.")
    if vm.available < (vm.total * 0.1):
        print("⚠ Available memory critically low.")


def memory_sampling(duration=5):
    print_section("MEMORY SAMPLING (5 Seconds)")

    samples = []

    for _ in range(duration):
        samples.append(psutil.virtual_memory().percent)
        time.sleep(1)

    print(f"{'Peak Usage':<25}: {max(samples)}%")
    print(f"{'Average Usage':<25}: {round(mean(samples), 2)}%")
    print(f"{'Lowest Usage':<25}: {min(samples)}%")


def show_top_memory_processes(limit=5):
    print_section("TOP MEMORY CONSUMERS")

    processes = []

    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            mem = proc.info['memory_info'].rss
            processes.append((proc.info['pid'], proc.info['name'], mem))
        except:
            continue

    processes.sort(key=lambda x: x[2], reverse=True)

    for pid, name, mem in processes[:limit]:
        print(f"{pid:<8} {name:<25} {round(mem / (1024**2), 2)} MB")



def show_process_memory_details(pid):
    try:
        proc = psutil.Process(pid)
        mem = proc.memory_info()

        print_section(f"MEMORY DETAILS FOR PID {pid}")

        print(f"{'Name':<25}: {proc.name()}")
        print(f"{'RSS (Physical)':<25}: {round(mem.rss / (1024**2), 2)} MB")
        print(f"{'VMS (Virtual)':<25}: {round(mem.vms / (1024**2), 2)} MB")
        print(f"{'Memory %':<25}: {round(proc.memory_percent(), 2)}%")

    except psutil.NoSuchProcess:
        print("Process not found.")



def show_ram_report():
    data = get_ram_details()

    print_section("SYSTEM MEMORY REPORT")

    print(f"{'Total RAM':<20}: {data['total']} GB")
    print(f"{'Available RAM':<20}: {data['available']} GB")
    print(f"{'Used RAM':<20}: {data['used']} GB")
    print(f"{'Free RAM':<20}: {data['free']} GB")
    print(f"{'Usage Percent':<20}: {data['percent']} %")

    print("\nSwap Memory:")
    print(f"{'Swap Total':<20}: {data['swap_total']} GB")
    print(f"{'Swap Used':<20}: {data['swap_used']} GB")
    print(f"{'Swap Free':<20}: {data['swap_free']} GB")
    print(f"{'Swap Usage':<20}: {data['swap_percent']} %")


# ==========================================================
# Suspicion Scoring (0–100)
# ==========================================================

def calculate_suspicion(process):
    score = 0

    try:
        cpu = process.cpu_percent(interval=0.1)
        memory = process.memory_percent()
        exe_path = process.exe()
        name = process.name()

        # High CPU
        if cpu > 50:
            score += 20

        # High memory
        if memory > 10:
            score += 20

        # Suspicious location
        if exe_path and any(folder in exe_path.lower() for folder in ["temp", "appdata", "downloads"]):
            score += 30

        # Random-looking name
        if re.match(r'^[a-zA-Z0-9]{10,}\.exe$', name):
            score += 10

        # Unsigned executable (basic heuristic)
        if exe_path and "program files" not in exe_path.lower():
            score += 10

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0, "UNKNOWN"

    # Determine level
    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


# ==========================================================
# Process Scan
# ==========================================================

def scan_processes():
    print_section("PROCESS SCAN REPORT")

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            score, level = calculate_suspicion(proc)

            print(f"PID: {proc.pid:<6} "
                  f"Name: {proc.name():<25} "
                  f"Score: {score:>3}/100 "
                  f"Risk: {level}")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


# ==========================================================
# Process Tree Investigation
# ==========================================================

def find_process(pid=None, name=None):
    if pid:
        try:
            return psutil.Process(pid)
        except psutil.NoSuchProcess:
            return None

    if name:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and proc.info['name'].lower() == name.lower():
                return proc

    return None


def show_process_tree(pid=None, name=None):
    process = find_process(pid, name)

    if not process:
        print("Process not found.")
        return

    print_section("PROCESS INVESTIGATION")

    print(f"Process: {process.name()} (PID: {process.pid})")

    # Parent
    parent = process.parent()
    if parent:
        print(f"Parent : {parent.name()} (PID: {parent.pid})")
    else:
        print("Parent : None")

    # Children
    children = process.children()
    if children:
        print("Children:")
        for child in children:
            print(f"   └── {child.name()} (PID: {child.pid})")
    else:
        print("Children: None")

    # Suspicion Score
    score, level = calculate_suspicion(process)
    print(f"\nSuspicion Score : {score}/100")
    print(f"Risk Level       : {level}")


# ==========================================================
# CLI Argument Parsing
# ==========================================================

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Professional Memory & Process Forensic Tool"
    )

    parser.add_argument("--ram", action="store_true", help="Show detailed RAM report")
    parser.add_argument("--scan", action="store_true", help="Scan all processes")
    parser.add_argument("--pid", type=int, help="Investigate process by PID")
    parser.add_argument("--name", type=str, help="Investigate process by name")
    parser.add_argument("--sys-sum", action="store_true", help="Show system summary")
    parser.add_argument("--ram-a", action="store_true", help="Show advanced RAM info")
    parser.add_argument("--health", action="store_true", help="Show memory health")
    parser.add_argument("--sample", action="store_true", help="Run memory sampling")


    return parser.parse_args()


# ==========================================================
# MAIN
# ==========================================================

def main():
    args = parse_arguments()

    print(f"\nTimestamp: {datetime.now()}\n")

    # No arguments → default behavior
    if not any(vars(args).values()):
        show_ram_report()
        scan_processes()
        show_system_summary()
        show_advanced_ram()
        memory_health_analysis()
        memory_sampling()
        show_top_memory_processes()
        return

    if args.ram:
        show_ram_report()

    if args.scan:
        scan_processes()

    if args.pid:
        show_process_tree(pid=args.pid)

    if args.name:
        show_process_tree(name=args.name)
    
    if args.sys_sum:
        show_system_summary()
    
    if args.ram_a:
        show_advanced_ram()

    if args.sample:
        memory_sampling()

    if args.health:
        memory_health_analysis()




if __name__ == "__main__":
    main()
