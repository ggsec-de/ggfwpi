"""Extracted GGFW component: hardware.platform."""


def detect_platform() -> str:
    try:
        with open('/proc/device-tree/model', 'r') as f:
            model = f.read().strip().rstrip('\x00')
            if 'Raspberry Pi 5' in model:
                return "Raspberry Pi 5 (BCM2712)"
            elif 'Raspberry Pi 4' in model:
                return "Raspberry Pi 4 (BCM2711)"
            elif 'Raspberry Pi 3' in model:
                return "Raspberry Pi 3 (BCM2837)"
            elif 'Raspberry Pi 2' in model:
                return "Raspberry Pi 2 (BCM2836)"
            elif 'Compute Module 5' in model:
                return "Compute Module 5 (BCM2712)"
            elif 'Compute Module 4' in model:
                return "Compute Module 4 (BCM2711)"
            elif 'Compute Module 3' in model:
                return "Compute Module 3 (BCM2837)"
            elif 'Raspberry Pi Zero 2' in model:
                return "Raspberry Pi Zero 2 W (BCM2710A1)"
            elif 'Raspberry Pi Zero' in model:
                return "Raspberry Pi Zero (BCM2835)"
            elif 'Raspberry Pi 1' in model:
                return "Raspberry Pi 1 (BCM2835)"
            else:
                return f"Raspberry Pi ({model})"
    except Exception:
        return "Unknown Raspberry Pi"

def get_soc_generation(platform: str) -> str:
    if "BCM2712" in platform:
        return "BCM2712"
    elif "BCM2711" in platform:
        return "BCM2711"
    elif "BCM2710" in platform:
        return "BCM2710"
    elif "BCM2837" in platform:
        return "BCM2837"
    elif "BCM2836" in platform:
        return "BCM2836"
    elif "BCM2835" in platform:
        return "BCM2835"
    return "Unknown"
