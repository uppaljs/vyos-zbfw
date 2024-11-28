# Python ZoBo - Zone Based Firewall Bootstrapper for VyOS

This is a Python port of [ZoBo](https://github.com/hasdf/zobo-vyos/tree/master), maintaining full compatibility with the original configuration format and functionality.

## Installation

```bash
git clone https://github.com/uppaljs/vyos-zbfw
cd vyos-zbfw
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration Format

The configuration uses YAML format. Example:

```yaml
zones:
  - wan
  - local
  - lan
  - mgmt

definitions:
  wan:
    interface: ["eth0"]
    description: "WAN Network"
    allow_ping_to: "local"
    allow_traffic_to:
      local:
        ports: ["22"]
  local:
    description: "Local Zone"
    is_local_zone: true
    allow_traffic_to: "*"
  lan:
    description: "LAN Network"
    interface: ["eth1"]
    allow_traffic_to:
      local:
        ports: ["53/tcp_udp"]
      wan:
```

### Configuration Options

#### Zone Definition

- `interface`: List of network interfaces
- `description`: Zone description
- `is_local_zone`: Boolean flag for local zone
- `allow_ping_to`: Target definition for ICMP traffic
- `allow_traffic_to`: Target definition for general traffic
- `default_action`: Either "drop" or "reject" (defaults to "drop")

#### Traffic Rules

Traffic rules can be defined in three ways:

1. Simple string: `allow_traffic_to: "local"`
2. List: `allow_traffic_to: ["local", "wan"]`
3. Detailed configuration:
```yaml
allow_traffic_to:
  local:
    ports: ["22", "80/tcp", "53/tcp_udp"]
    addresses: ["192.168.1.1", "10.0.0.1"]
```

#### Special Values

- `"*"`: Wildcard, allows traffic to all zones
- `tcp_udp`: Special protocol value for both TCP and UDP

## Usage

```bash
python3 generate.py [-h] [-c CONFIG] [-q] [-i] [-d] [-s]
```

### Command Line Options

- `-c, --config`: Path to config file (default: zones.yaml)
- `-q, --quiet`: Hide info messages
- `-i, --log-invalid`: Enable logging of invalid packets
- `-d, --disable-default-logs`: Disable default logging
- `-s, --strip-duplicates`: Remove redundant rules that match default action

### Output

The script generates VyOS commands that can be directly applied to configure zone-based firewalls.

Example output:
```bash
set firewall zone 'wan' default-action 'drop'
set firewall zone 'wan' description 'WAN Network'
set firewall zone 'wan' interface 'eth0'
...
```

## License

This project is licensed under the AGPLv3 License, maintaining compatibility with the original ZoBo project.
