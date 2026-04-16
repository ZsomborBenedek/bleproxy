# BLE Proxy MITM

This project is a BLE man-in-the-middle proxy built with Bleak and BlueZ D-Bus. It can scan for nearby devices or connect to a target, mirror its GATT structure, and expose a fake peripheral that forwards traffic through the proxy.

## Disclaimer

This repository is intended for educational and research purposes only. Use it only on systems and devices you own or have explicit permission to test. Misuse may violate law, policy, or third-party terms.

## Requirements

- Linux with BlueZ
- Python 3.12 or compatible
- Root or sufficient privileges for Bluetooth adapter access
- `bleak`, `dbus`, `gi`, and related Bluetooth dependencies

The project includes a virtual environment in `bleproxy-venv/`.

## Usage

Scan for nearby BLE devices:

```bash
sudo python3 ble_mitm.py --scan
```

Scan on a specific adapter:

```bash
sudo python3 ble_mitm.py --scan --adapter hci3
```

Run the proxy against a target device:

```bash
sudo python3 ble_mitm.py --target FF:56:E4:83:18:1E
```

Run the proxy with explicit adapters:

```bash
sudo python3 ble_mitm.py --target FF:56:E4:83:18:1E --central hci3 --peripheral hci4
```

## Runtime Notes

- The script prompts you to put the target device into pairing mode before connecting.
- Logs are written to `logs/mitm_<target>.log`.
- Raw HCI capture from `btmon` is written to `logs/btmon_<adapter>.log` when available.
- The proxy currently names the fake peripheral using the target device name with ` - Fake` appended.

## Project Files

- `ble_mitm.py`: Main scanner and MITM proxy implementation.
- `client_debug.py`: Auxiliary client/debug helper.
- `prototypes/`: Experimental scripts and earlier proxy variants.

## Notes

This tool is a working proxy implementation, not a polished package. Some behavior is highly environment-dependent and may require matching adapter support, BlueZ version compatibility, and target-specific GATT quirks.
