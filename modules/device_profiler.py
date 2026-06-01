"""
Module 3: Device Identification & Profiling
Identifies connected hosts and infers device types
"""

import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)


class DeviceProfiler:
    """Identifies and profiles network devices"""
    
    def __init__(self, features_df):
        """
        Initialize device profiler
        
        Args:
            features_df: DataFrame with extracted features
        """
        self.features = features_df.copy()
        self.devices = {}
        self.device_profiles = None
        
    def identify_hosts(self):
        """Identify all unique hosts in the network"""
        # Identify unique source IPs (likely local devices)
        local_devices = self.features['src_ip'].unique()
        
        logger.info(f"Identified {len(local_devices)} unique hosts")
        return local_devices
    
    def profile_devices(self):
        """Create profiles for identified devices"""
        devices = self.identify_hosts()
        
        profiles = []
        
        for device_ip in devices:
            # Get all traffic from this device
            device_traffic = self.features[self.features['src_ip'] == device_ip]
            
            if len(device_traffic) == 0:
                continue
            
            profile = {
                'device_ip': device_ip,
                'device_mac': device_traffic['src_mac'].iloc[0],
                'packet_count': len(device_traffic),
                'first_seen': device_traffic['timestamp'].min(),
                'last_seen': device_traffic['timestamp'].max(),
                'protocols_used': device_traffic['protocol'].unique().tolist(),
                'avg_packet_size': device_traffic['packet_size'].mean(),
                'total_data_sent': device_traffic['packet_size'].sum(),
                'destination_ips': device_traffic['dst_ip'].nunique(),
                'unique_ports_used': device_traffic['src_port'].nunique(),
                'encrypted_traffic_ratio': device_traffic['encrypted_flag'].mean(),
                'tls_versions_used': device_traffic[device_traffic['encrypted_flag'] == 1]['tls_version'].unique().tolist(),
            }
            
            # Infer device type
            profile['inferred_type'] = self._infer_device_type(profile)
            
            profiles.append(profile)
        
        self.device_profiles = pd.DataFrame(profiles)
        logger.info(f"Profiled {len(profiles)} devices")
        return self.device_profiles
    
    def _infer_device_type(self, profile):
        """
        Infer device type based on behavior heuristics
        
        Args:
            profile: Device profile dictionary
            
        Returns:
            str: Inferred device type
        """
        # Heuristic-based classification
        
        # IoT devices: frequent communication, small packets, specific protocols
        if (profile['packet_count'] > 1000 and 
            profile['avg_packet_size'] < 128 and
            'UDP' in profile['protocols_used']):
            return 'IoT Device'
        
        # Servers: many connections, encrypted traffic
        if (profile['destination_ips'] > 20 and
            profile['encrypted_traffic_ratio'] > 0.7):
            return 'Server'
        
        # Workstations: moderate activity, mixed protocols
        if (200 < profile['packet_count'] < 5000 and
            len(profile['protocols_used']) > 1):
            return 'Workstation'
        
        # Mobile devices: intermittent, encrypted
        if (profile['encrypted_traffic_ratio'] > 0.8 and
            profile['packet_count'] < 500):
            return 'Mobile Device'
        
        # Printers/Scanners: periodic bursts
        if (profile['packet_count'] < 200 and
            'TCP' in profile['protocols_used']):
            return 'Printer/Scanner'
        
        return 'Unknown'
    
    def get_device_summary(self, device_ip):
        """Get summary for a specific device"""
        if self.device_profiles is None:
            self.profile_devices()
        
        device = self.device_profiles[self.device_profiles['device_ip'] == device_ip]
        
        if len(device) == 0:
            return None
        
        return device.iloc[0].to_dict()
    
    def get_all_devices(self):
        """Get profiles for all devices"""
        if self.device_profiles is None:
            self.profile_devices()
        
        return self.device_profiles
    
    def get_device_by_type(self, device_type):
        """Get all devices of a specific type"""
        if self.device_profiles is None:
            self.profile_devices()
        
        return self.device_profiles[self.device_profiles['inferred_type'] == device_type]
    
    def get_statistics(self):
        """Get device statistics"""
        if self.device_profiles is None:
            self.profile_devices()
        
        stats = {
            'total_devices': len(self.device_profiles),
            'device_types': self.device_profiles['inferred_type'].value_counts().to_dict(),
            'avg_packets_per_device': self.device_profiles['packet_count'].mean(),
            'avg_encryption_ratio': self.device_profiles['encrypted_traffic_ratio'].mean(),
            'devices_with_encryption': (self.device_profiles['encrypted_traffic_ratio'] > 0).sum(),
        }
        
        return stats
    
    def export_device_profiles(self, output_path):
        """Export device profiles to CSV"""
        if self.device_profiles is None:
            self.profile_devices()
        
        # Convert list columns to string for CSV export
        df = self.device_profiles.copy()
        df['protocols_used'] = df['protocols_used'].apply(str)
        df['tls_versions_used'] = df['tls_versions_used'].apply(str)
        
        df.to_csv(output_path, index=False)
        logger.info(f"Device profiles exported to {output_path}")


if __name__ == "__main__":
    # Example usage
    import sys
    sys.path.insert(0, '/home/claude')
    from traffic_acquisition import TrafficAcquisition
    from packet_parser import PacketParser
    
    # Generate and parse data
    acq = TrafficAcquisition()
    data = acq.create_synthetic_dataset(2000)
    
    parser = PacketParser(data)
    features = parser.extract_all_features()
    
    # Profile devices
    profiler = DeviceProfiler(features)
    profiles = profiler.profile_devices()
    
    print("\nDevice Profiles:")
    print(profiles[['device_ip', 'packet_count', 'encrypted_traffic_ratio', 'inferred_type']])
    
    print("\nStatistics:")
    print(profiler.get_statistics())
