#!/usr/bin/env python3
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Union
import argparse
import ipaddress
import yaml
import sys
from pathlib import Path

# Enums
class ZoneDefaultAction(Enum):
    DROP = "drop"
    REJECT = "reject"

class FirewallAction(Enum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"

class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    TCP_UDP = "tcp_udp"
    ICMP = "icmp"
    ALL = "all"

class State(Enum):
    ESTABLISHED = "established"
    INVALID = "invalid"
    NEW = "new"
    RELATED = "related"

# Constants
WILDCARD = "*"

# Data Models
@dataclass
class TargetWhitelist:
    name: str
    allowed_ports: List[str] = None
    allowed_addresses: List[str] = None

    def __post_init__(self):
        self.allowed_ports = self.allowed_ports or []
        self.allowed_addresses = self.allowed_addresses or []
        # Convert string addresses to IP objects
        self.allowed_addresses = [ipaddress.ip_address(addr) for addr in self.allowed_addresses]

class TargetDefinition:
    def __init__(self, allowed_targets: List[TargetWhitelist] = None):
        self.allowed_targets = allowed_targets or []

    @classmethod
    def get_target_definition(cls, targets) -> 'TargetDefinition':
        if not targets:
            return cls([])  # None case
        if isinstance(targets, str):
            return cls([TargetWhitelist(targets)])
        if isinstance(targets, list):
            if isinstance(targets[0], str):
                return cls([TargetWhitelist(t) for t in targets])
        if isinstance(targets, dict):
            whitelists = [
                TargetWhitelist(
                    name=name,
                    allowed_ports=details.get('ports', []),
                    allowed_addresses=details.get('addresses', [])
                )
                for name, details in targets.items()
            ]
            return cls(whitelists)
        return cls([])

    def is_wildcard(self) -> bool:
        return len(self.allowed_targets) == 1 and self.allowed_targets[0].name == WILDCARD

    def is_none(self) -> bool:
        return not self.allowed_targets

@dataclass
class Zone:
    interface: Optional[List[str]] = None
    description: Optional[str] = None
    is_local_zone: bool = False
    allow_ping_to: Optional[TargetDefinition] = None
    allow_traffic_to: Optional[TargetDefinition] = None
    default_action: ZoneDefaultAction = ZoneDefaultAction.DROP

    @classmethod
    def from_dict(cls, data: dict) -> 'Zone':
        return cls(
            interface=data.get('interface'),
            description=data.get('description'),
            is_local_zone=data.get('is_local_zone', False),
            allow_ping_to=TargetDefinition.get_target_definition(data.get('allow_ping_to')),
            allow_traffic_to=TargetDefinition.get_target_definition(data.get('allow_traffic_to')),
            default_action=ZoneDefaultAction[data.get('default_action', 'DROP').upper()]
        )

class NetworkTarget:
    def __str__(self) -> str:
        raise NotImplementedError()

class IPTarget(NetworkTarget):
    def __init__(self, ip: ipaddress.IPv4Address):
        self.ip = ip

    def __str__(self) -> str:
        return f"address {self.ip}"

class PortTarget(NetworkTarget):
    def __init__(self, port: int):
        self.port = port

    def __str__(self) -> str:
        return f"port {self.port}"

@dataclass
class FirewallRule:
    action: Optional[FirewallAction] = None
    state: Optional[List[State]] = None
    protocol: Optional[Protocol] = None
    destination: Optional[NetworkTarget] = None
    description: Optional[str] = None
    log: bool = False

    def to_vyos_commands(self, prefix: str) -> List[str]:
        commands = []
        
        if self.action:
            commands.append(f"{prefix} action {self.action.value}")
        
        if self.state:
            for state in self.state:
                commands.append(f"{prefix} state {state.value}")
        
        if self.protocol:
            commands.append(f"{prefix} protocol {self.protocol.value}")
        
        if self.description:
            commands.append(f"{prefix} description '{self.description}'")
        
        if self.log:
            commands.append(f"{prefix} log enable")
        
        if self.destination:
            commands.append(f"{prefix} destination {str(self.destination)}")
        
        return commands

class FirewallConfiguration:
    class RuleNumberMapping(Enum):
        ALLOW_ESTABLISHED = 10
        LOG_INVALID_PACKETS = 11
        ALLOW_PING = 15
        CUSTOM_RULE_RANGE_START = 50

    def __init__(self, name: str, options: dict, default_action: FirewallAction = FirewallAction.DROP):
        self.name = name
        self.default_action = default_action
        self.options = options
        self.firewall_rules: Dict[int, FirewallRule] = {}
        self.next_rule_number = self.RuleNumberMapping.CUSTOM_RULE_RANGE_START.value
        self.add_default_rules()

    def add_default_rules(self):
        # Allow established connections
        self.firewall_rules[self.RuleNumberMapping.ALLOW_ESTABLISHED.value] = FirewallRule(
            action=FirewallAction.ACCEPT,
            description="Allow established connections",
            state=[State.ESTABLISHED, State.RELATED]
        )

        # Log invalid packets if enabled
        if self.options.get('log_invalid_packets', False):
            self.firewall_rules[self.RuleNumberMapping.LOG_INVALID_PACKETS.value] = FirewallRule(
                action=FirewallAction.DROP,
                description="Log invalid packages",
                state=[State.INVALID],
                log=True
            )

    def allow_traffic(self, ports: List[str] = None, addresses: List[ipaddress.IPv4Address] = None):
        if not ports and not addresses:
            self.default_action = FirewallAction.ACCEPT
            return

        # Add port rules
        if ports:
            for port in ports:
                protocol = Protocol.TCP
                if '/' in port:
                    port, proto = port.split('/')
                    protocol = Protocol[proto.upper()]
                
                self.firewall_rules[self.next_rule_number] = FirewallRule(
                    action=FirewallAction.ACCEPT,
                    protocol=protocol,
                    destination=PortTarget(int(port))
                )
                self.next_rule_number += 1

        # Add address rules
        if addresses:
            for address in addresses:
                self.firewall_rules[self.next_rule_number] = FirewallRule(
                    action=FirewallAction.ACCEPT,
                    destination=IPTarget(address)
                )
                self.next_rule_number += 1

    def allow_ping(self):
        if self.RuleNumberMapping.ALLOW_PING.value not in self.firewall_rules:
            self.firewall_rules[self.RuleNumberMapping.ALLOW_PING.value] = FirewallRule(
                action=FirewallAction.ACCEPT,
                description="Allow pings",
                protocol=Protocol.ICMP
            )

    def to_vyos_commands(self) -> List[str]:
        commands = []
        prefix = f"set firewall ipv4 name '{self.name}'"
        
        # Default action
        commands.append(f"{prefix} default-action {self.default_action.value}")
        
        # Default logs if enabled
        if not self.options.get('disable_default_logs', False) and self.default_action != FirewallAction.ACCEPT:
            commands.append(f"{prefix} enable-default-log")
        
        # Add rules
        for rule_number, rule in sorted(self.firewall_rules.items()):
            if not self.options.get('strip_duplicate_rules', False) or self.default_action != rule.action:
                rule_prefix = f"{prefix} rule {rule_number}"
                commands.extend(rule.to_vyos_commands(rule_prefix))
        
        return commands

class VyOSConfiguration:
    def __init__(self, zone_config: dict, options: dict):
        self.options = options
        self.zones = zone_config.get('zones', [])
        self.zone_definitions = {
            name: Zone.from_dict(definition)
            for name, definition in zone_config.get('definitions', {}).items()
        }
        
        # Initialize configurations
        self.firewall_configs: Dict[str, Dict[str, FirewallConfiguration]] = {}
        self.initialize_configurations()
        self.configure_zones()

    def initialize_configurations(self):
        for source_zone in self.zones:
            self.firewall_configs[source_zone] = {}
            for target_zone in self.zones:
                if source_zone != target_zone:
                    self.firewall_configs[source_zone][target_zone] = FirewallConfiguration(
                        f"{source_zone}-{target_zone}",
                        self.options
                    )

    def configure_zones(self):
        for zone_name, definition in self.zone_definitions.items():
            # Configure ping rules
            if definition.allow_ping_to:
                pingable_zones = (
                    [TargetWhitelist(z) for z in self.zones if z != zone_name]
                    if definition.allow_ping_to.is_wildcard()
                    else definition.allow_ping_to.allowed_targets
                )
                
                for pingable_zone in pingable_zones:
                    self.firewall_configs[zone_name][pingable_zone.name].allow_ping()

            # Configure traffic rules
            if definition.allow_traffic_to:
                whitelisted_zones = (
                    [TargetWhitelist(z) for z in self.zones if z != zone_name]
                    if definition.allow_traffic_to.is_wildcard()
                    else definition.allow_traffic_to.allowed_targets
                )
                
                for whitelisted_zone in whitelisted_zones:
                    if whitelisted_zone.name == WILDCARD:
                        for target_zone in self.zones:
                            if target_zone != zone_name:
                                self.firewall_configs[zone_name][target_zone].allow_traffic(
                                    whitelisted_zone.allowed_ports,
                                    whitelisted_zone.allowed_addresses
                                )
                    else:
                        self.firewall_configs[zone_name][whitelisted_zone.name].allow_traffic(
                            whitelisted_zone.allowed_ports,
                            whitelisted_zone.allowed_addresses
                        )

    def generate_commands(self) -> List[str]:
        commands = []
        
        # Zone configurations
        for zone_name, definition in self.zone_definitions.items():
            prefix = f"set firewall zone '{zone_name}'"
            commands.append(f"{prefix} default-action '{definition.default_action.value}'")
            
            if definition.description:
                commands.append(f"{prefix} description '{definition.description}'")
            
            if definition.interface:
                for iface in definition.interface:
                    commands.append(f"{prefix} interface '{iface}'")
            
            if definition.is_local_zone:
                commands.append(f"{prefix} local-zone")

        # Firewall rules
        for source_zone, targets in self.firewall_configs.items():
            for target_zone, firewall_config in targets.items():
                commands.extend(firewall_config.to_vyos_commands())
                commands.append(
                    f"set firewall zone {target_zone} from {source_zone} "
                    f"firewall name {firewall_config.name}"
                )

        return commands

def main():
    parser = argparse.ArgumentParser(description='ZoBo - Zone Based Firewall Bootstrapper for VyOS')
    parser.add_argument('-c', '--config', default='zones.yaml',
                      help='Path to the config file (default: zones.yaml)')
    parser.add_argument('-q', '--quiet', action='store_true',
                      help='Hide info messages. Only outputs the generated vyos commands')
    parser.add_argument('-i', '--log-invalid', action='store_true',
                      help='Set to true if you want to log invalid packets')
    parser.add_argument('-d', '--disable-default-logs', action='store_true',
                      help='Set to true if you dont want to enable default logs')
    parser.add_argument('-s', '--strip-duplicates', action='store_true',
                      help='Set to true if you dont want to get any rules which action matches the firewalls default action')

    args = parser.parse_args()

    # Read and parse configuration file
    try:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Error: Config file {args.config} not found", file=sys.stderr)
            sys.exit(1)

        with open(config_path) as f:
            config = yaml.safe_load(f)

    except Exception as e:
        print(f"Error reading config file: {e}", file=sys.stderr)
        sys.exit(1)

    # Create options dictionary
    options = {
        'log_invalid_packets': args.log_invalid,
        'disable_default_logs': args.disable_default_logs,
        'strip_duplicate_rules': args.strip_duplicates,
        'quiet': args.quiet
    }

    # Generate and print VyOS configuration
    try:
        vyos_config = VyOSConfiguration(config, options)
        for command in vyos_config.generate_commands():
            print(command)

    except Exception as e:
        print(f"Error generating configuration: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
