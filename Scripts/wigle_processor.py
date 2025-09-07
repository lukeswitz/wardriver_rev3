#!/usr/bin/env python3
"""
WiGLE CSV Processor - A Python tool for processing wardriving CSV files

This tool replaces the original shell scripts with a clean Python implementation
for filtering, analyzing, and processing WiGLE-format CSV files.
"""

import argparse
import csv
import json
import os
import shutil
import sys
from collections import defaultdict, Counter
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
import re


@dataclass
class WiGLERecord:
    """Represents a single WiGLE CSV record"""
    mac: str
    ssid: str
    auth_mode: str
    first_seen: str
    channel: str
    rssi: str
    latitude: float
    longitude: float
    altitude: str
    accuracy: str
    network_type: str
    
    @classmethod
    def from_csv_row(cls, row: List[str]) -> Optional['WiGLERecord']:
        """Create a WiGLERecord from a CSV row"""
        if len(row) < 11:
            return None
        
        try:
            # Handle potential parsing issues
            lat = float(row[6]) if row[6] else 0.0
            lon = float(row[7]) if row[7] else 0.0
            
            return cls(
                mac=row[0],
                ssid=row[1], 
                auth_mode=row[2],
                first_seen=row[3],
                channel=row[4],
                rssi=row[5],
                latitude=lat,
                longitude=lon,
                altitude=row[8],
                accuracy=row[9],
                network_type=row[10] if len(row) > 10 else "WIFI"
            )
        except (ValueError, IndexError):
            return None


class LocationFilter:
    """Handles geolocation-based filtering"""
    
    def __init__(self, my_lat: float, my_long: float, delta: float = 0.001):
        self.my_lat = my_lat
        self.my_long = my_long
        self.delta = delta
        
        self.lat_min = my_lat - delta
        self.lat_max = my_lat + delta
        self.long_min = my_long - delta
        self.long_max = my_long + delta
    
    def is_here(self, record: WiGLERecord) -> bool:
        """Check if a record is within the local area"""
        if record.latitude == 0 and record.longitude == 0:
            return False
            
        return (self.lat_min <= record.latitude <= self.lat_max and 
                self.long_min <= record.longitude <= self.long_max)
    
    def is_not_here(self, record: WiGLERecord) -> bool:
        """Check if a record is outside the local area"""
        if record.latitude == 0 and record.longitude == 0:
            return False
        return not self.is_here(record)


class FilterConfig:
    """Configuration for filtering MACs and SSIDs"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.blocked_macs: Set[str] = set()
        self.blocked_ssids: Set[str] = set()
        self.blocked_patterns: List[re.Pattern] = []
        
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
    
    def load_config(self, config_file: str):
        """Load filter configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                
            self.blocked_macs = set(config.get('blocked_macs', []))
            self.blocked_ssids = set(config.get('blocked_ssids', []))
            
            # Compile regex patterns
            for pattern in config.get('blocked_patterns', []):
                try:
                    self.blocked_patterns.append(re.compile(pattern))
                except re.error as e:
                    print(f"Warning: Invalid regex pattern '{pattern}': {e}")
                    
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Warning: Could not load config file {config_file}: {e}")
    
    def should_filter(self, record: WiGLERecord) -> bool:
        """Check if a record should be filtered out"""
        # Check MAC address
        if record.mac.upper() in self.blocked_macs:
            return True
            
        # Check SSID
        if record.ssid in self.blocked_ssids:
            return True
            
        # Check patterns
        for pattern in self.blocked_patterns:
            if pattern.search(record.ssid) or pattern.search(record.mac):
                return True
                
        return False
    
    def create_sample_config(self, config_file: str):
        """Create a sample configuration file"""
        sample_config = {
            "blocked_macs": [
                "FF:FF:FF:FF:FF:FF",
                "aa:bb:cc:dd:ee:ff"
            ],
            "blocked_ssids": [
                "myssid",
                "wardriver.uk"
            ],
            "blocked_patterns": [
                "MyCompany.*",
                ".*test.*"
            ]
        }
        
        with open(config_file, 'w') as f:
            json.dump(sample_config, f, indent=2)
        print(f"Sample configuration created: {config_file}")


class CreepDetector:
    """Detects devices seen at multiple locations (potential stalkers)"""
    
    def __init__(self, fudge_factor: int = 100):
        self.fudge_factor = fudge_factor
        self.mac_locations: Dict[str, Set[str]] = defaultdict(set)
    
    def add_record(self, record: WiGLERecord):
        """Add a record for processing"""
        if record.latitude == 0 and record.longitude == 0:
            return
            
        # Round coordinates to reduce GPS precision noise
        lat = int((record.latitude * self.fudge_factor) + 0.5) / self.fudge_factor
        lon = int((record.longitude * self.fudge_factor) - 0.5) / self.fudge_factor
        
        location = f"{lat:.2f} {lon:.2f}"
        self.mac_locations[record.mac].add(location)
    
    def get_multi_location_devices(self, min_locations: int = 2) -> List[Tuple[int, str]]:
        """Get devices seen at multiple locations"""
        results = []
        for mac, locations in self.mac_locations.items():
            if len(locations) >= min_locations:
                results.append((len(locations), mac))
        
        return sorted(results, reverse=True)


class EncryptionAnalyzer:
    """Analyzes encryption types in the dataset"""
    
    def __init__(self):
        self.encryption_counts: Counter = Counter()
        self.unique_networks: Set[str] = set()
    
    def add_record(self, record: WiGLERecord):
        """Add a record for analysis"""
        # Use MAC + SSID as unique identifier
        network_id = f"{record.mac} {record.ssid}"
        
        if network_id not in self.unique_networks:
            self.unique_networks.add(network_id)
            self.encryption_counts[record.auth_mode] += 1
    
    def get_stats(self) -> Dict[str, Dict[str, float]]:
        """Get encryption statistics"""
        total = sum(self.encryption_counts.values())
        if total == 0:
            return {}
        
        stats = {}
        for enc_type, count in self.encryption_counts.items():
            percentage = (count / total) * 100
            stats[enc_type] = {
                'count': count,
                'percentage': percentage,
                'total': total
            }
        
        return stats


class WiGLEProcessor:
    """Main processor for WiGLE CSV files"""
    
    def __init__(self):
        self.location_filter: Optional[LocationFilter] = None
        self.filter_config: Optional[FilterConfig] = None
    
    def set_location_filter(self, lat: float, lon: float, delta: float = 0.001):
        """Set location-based filtering"""
        self.location_filter = LocationFilter(lat, lon, delta)
    
    def set_filter_config(self, config_file: str):
        """Set MAC/SSID filtering configuration"""
        self.filter_config = FilterConfig(config_file)
    
    def read_csv_file(self, filename: str) -> List[WiGLERecord]:
        """Read and parse a WiGLE CSV file"""
        records = []
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                # Skip header lines
                lines = f.readlines()
                data_start = 0
                
                # Find where data starts (after headers)
                for i, line in enumerate(lines):
                    if line.startswith('MAC,SSID') or 'MAC' in line and 'SSID' in line:
                        data_start = i + 1
                        break
                
                # Parse CSV data
                reader = csv.reader(lines[data_start:])
                for row in reader:
                    if not row or len(row) < 11:
                        continue
                        
                    record = WiGLERecord.from_csv_row(row)
                    if record:
                        records.append(record)
                        
        except (FileNotFoundError, UnicodeDecodeError) as e:
            print(f"Error reading file {filename}: {e}")
            
        return records
    
    def filter_records(self, records: List[WiGLERecord], 
                      location_mode: str = None) -> List[WiGLERecord]:
        """Apply filters to records"""
        filtered = []
        
        for record in records:
            # Apply MAC/SSID filtering
            if self.filter_config and self.filter_config.should_filter(record):
                continue
            
            # Apply location filtering
            if self.location_filter and location_mode:
                if location_mode == 'here' and not self.location_filter.is_here(record):
                    continue
                elif location_mode == 'not_here' and not self.location_filter.is_not_here(record):
                    continue
            
            filtered.append(record)
        
        return filtered
    
    def write_csv_file(self, filename: str, records: List[WiGLERecord]):
        """Write records to a CSV file"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            # Write WiGLE headers
            f.write("WiGLE.net Python Processor\n")
            f.write("MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n")
            
            writer = csv.writer(f)
            for record in records:
                writer.writerow([
                    record.mac, record.ssid, record.auth_mode,
                    record.first_seen, record.channel, record.rssi,
                    record.latitude, record.longitude, record.altitude,
                    record.accuracy, record.network_type
                ])


def main():
    parser = argparse.ArgumentParser(description='WiGLE CSV Processor')
    parser.add_argument('files', nargs='*', help='CSV files to process')
    
    # Main operations
    parser.add_argument('--scrub', action='store_true', 
                       help='Filter and scrub CSV files')
    parser.add_argument('--creeps', action='store_true',
                       help='Find devices at multiple locations')
    parser.add_argument('--encryption', action='store_true',
                       help='Analyze encryption statistics')
    parser.add_argument('--here', action='store_true',
                       help='Filter for local area only')
    parser.add_argument('--not-here', action='store_true',
                       help='Filter for non-local area only')
    
    # Configuration
    parser.add_argument('--lat', type=float, help='Your latitude')
    parser.add_argument('--lon', type=float, help='Your longitude') 
    parser.add_argument('--delta', type=float, default=0.001,
                       help='Location delta (default: 0.001)')
    parser.add_argument('--config', help='Filter configuration file')
    parser.add_argument('--create-config', help='Create sample config file')
    parser.add_argument('--output-dir', default='./Scrub',
                       help='Output directory for scrubbed files')
    
    args = parser.parse_args()
    
    if args.create_config:
        FilterConfig().create_sample_config(args.create_config)
        return
    
    if not args.files and not args.creeps and not args.encryption:
        # If no files specified, look for *.csv in current directory
        args.files = list(Path('.').glob('*.csv'))
    
    if not args.files:
        print("No CSV files found. Use --help for usage information.")
        return
    
    processor = WiGLEProcessor()
    
    # Set up location filtering if coordinates provided
    if args.lat is not None and args.lon is not None:
        processor.set_location_filter(args.lat, args.lon, args.delta)
    
    # Set up MAC/SSID filtering
    if args.config:
        processor.set_filter_config(args.config)
    
    all_records = []
    
    # Read all files
    for filename in args.files:
        print(f"Reading {filename}...")
        records = processor.read_csv_file(str(filename))
        all_records.extend(records)
        
        # Process individual files for scrubbing
        if args.scrub:
            location_mode = None
            if args.here:
                location_mode = 'here'
            elif args.not_here:
                location_mode = 'not_here'
            
            filtered = processor.filter_records(records, location_mode)
            
            # Write scrubbed file
            output_file = Path(args.output_dir) / filename
            processor.write_csv_file(str(output_file), filtered)
            print(f"Scrubbed {filename} -> {output_file} ({len(filtered)}/{len(records)} records)")
    
    # Global analysis operations
    if args.creeps:
        print("\nFinding devices at multiple locations...")
        detector = CreepDetector()
        for record in all_records:
            detector.add_record(record)
        
        multi_location = detector.get_multi_location_devices()
        
        print(f"\n{'Locations':<12} {'MAC Address':<18}")
        print("-" * 30)
        for count, mac in multi_location[:10]:  # Top 10
            print(f"{count:<12} {mac}")
            
            # Show sample locations for this MAC
            print("Sample records:")
            sample_count = 0
            for record in all_records:
                if record.mac == mac and sample_count < 3:
                    print(f"  {record.latitude:.6f}, {record.longitude:.6f} - {record.ssid}")
                    sample_count += 1
            print()
    
    if args.encryption:
        print("\nAnalyzing encryption types...")
        analyzer = EncryptionAnalyzer()
        for record in all_records:
            analyzer.add_record(record)
        
        stats = analyzer.get_stats()
        
        print(f"\n{'Encryption':<20} {'Percentage':<12} {'Count':<8} {'Total'}")
        print("-" * 50)
        for enc_type, data in sorted(stats.items(), key=lambda x: x[1]['count'], reverse=True):
            print(f"{enc_type:<20} {data['percentage']:>8.2f}%   {data['count']:>6}/{data['total']}")


if __name__ == '__main__':
    main()
