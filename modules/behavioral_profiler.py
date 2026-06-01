"""
Module 7: Behavioral Profiling
Creates traffic behavior profiles per device and detects anomalies
"""

import pandas as pd
import numpy as np
import logging
from datetime import timedelta

logger = logging.getLogger(__name__)


class BehavioralProfiler:
    """Creates behavioral profiles of network devices"""
    
    def __init__(self, features_df):
        """
        Initialize behavioral profiler
        
        Args:
            features_df: DataFrame with extracted features
        """
        self.features = features_df.copy()
        self.device_profiles = None
        
    def create_device_profiles(self):
        """Create behavioral profiles for each device"""
        profiles = {}
        
        for device_ip in self.features['src_ip'].unique():
            device_traffic = self.features[self.features['src_ip'] == device_ip]
            
            profile = {
                'device_ip': device_ip,
                'profile_data': self._extract_behavior_features(device_traffic)
            }
            
            profiles[device_ip] = profile
        
        self.device_profiles = profiles
        logger.info(f"Created behavioral profiles for {len(profiles)} devices")
        return profiles
    
    def _extract_behavior_features(self, device_traffic):
        """Extract behavioral features from device traffic"""
        if len(device_traffic) == 0:
            return None
        
        # Convert timestamp to datetime
        device_traffic = device_traffic.copy()
        if not pd.api.types.is_datetime64_any_dtype(device_traffic['timestamp']):
            device_traffic['timestamp'] = pd.to_datetime(device_traffic['timestamp'])
        
        # Protocol usage
        protocol_distribution = device_traffic['protocol'].value_counts().to_dict()
        
        # Port usage
        port_distribution = device_traffic['dst_port'].value_counts().head(10).to_dict()
        
        # Traffic volume over time
        device_traffic['hour'] = device_traffic['timestamp'].dt.hour
        hourly_traffic = device_traffic.groupby('hour')['packet_size'].sum().to_dict()
        
        # Encryption behavior
        encryption_ratio = device_traffic['encrypted_flag'].mean()
        encrypted_ports = device_traffic[device_traffic['encrypted_flag'] == 1]['dst_port'].unique()
        
        # Destination behavior
        unique_destinations = device_traffic['dst_ip'].nunique()
        destination_ips = device_traffic['dst_ip'].unique().tolist()
        
        # Communication pattern
        packet_rate = len(device_traffic) / max((device_traffic['timestamp'].max() - device_traffic['timestamp'].min()).total_seconds(), 1)
        avg_packet_size = device_traffic['packet_size'].mean()
        
        profile = {
            'total_packets': len(device_traffic),
            'total_bytes': device_traffic['packet_size'].sum(),
            'unique_destinations': unique_destinations,
            'unique_ports_used': device_traffic['dst_port'].nunique(),
            'protocols_used': list(protocol_distribution.keys()),
            'protocol_distribution': protocol_distribution,
            'top_ports': port_distribution,
            'encryption_ratio': round(encryption_ratio, 3),
            'encrypted_ports': encrypted_ports.tolist(),
            'packet_rate': round(packet_rate, 2),
            'avg_packet_size': round(avg_packet_size, 2),
            'hourly_distribution': hourly_traffic,
            'first_activity': device_traffic['timestamp'].min(),
            'last_activity': device_traffic['timestamp'].max(),
        }
        
        return profile
    
    def analyze_protocol_distribution(self, device_ip):
        """Analyze protocol usage for a specific device"""
        if self.device_profiles is None:
            self.create_device_profiles()
        
        if device_ip not in self.device_profiles:
            return None
        
        profile = self.device_profiles[device_ip]['profile_data']
        return profile['protocol_distribution'] if profile else None
    
    def analyze_temporal_pattern(self, device_ip):
        """Analyze temporal traffic patterns"""
        if self.device_profiles is None:
            self.create_device_profiles()
        
        if device_ip not in self.device_profiles:
            return None
        
        profile = self.device_profiles[device_ip]['profile_data']
        return profile['hourly_distribution'] if profile else None
    
    def get_device_behavior_summary(self, device_ip):
        """Get behavioral summary for a device"""
        if self.device_profiles is None:
            self.create_device_profiles()
        
        if device_ip not in self.device_profiles:
            return None
        
        return self.device_profiles[device_ip]['profile_data']
    
    def compare_devices(self):
        """Compare behavior across devices"""
        if self.device_profiles is None:
            self.create_device_profiles()
        
        comparison = []
        
        for device_ip, device_data in self.device_profiles.items():
            profile = device_data['profile_data']
            
            if profile:
                comparison.append({
                    'device_ip': device_ip,
                    'total_packets': profile['total_packets'],
                    'total_bytes': profile['total_bytes'],
                    'unique_destinations': profile['unique_destinations'],
                    'encryption_ratio': profile['encryption_ratio'],
                    'avg_packet_size': profile['avg_packet_size'],
                    'packet_rate': profile['packet_rate'],
                })
        
        comparison_df = pd.DataFrame(comparison).sort_values('total_packets', ascending=False)
        logger.info(f"Compared behavior of {len(comparison_df)} devices")
        return comparison_df
    
    def identify_unusual_behavior(self):
        """Identify devices with unusual behavior"""
        comparison = self.compare_devices()
        
        if comparison.empty:
            return pd.DataFrame()
        
        unusual = []
        
        # Calculate statistics
        for column in ['total_packets', 'unique_destinations', 'packet_rate']:
            if column not in comparison.columns:
                continue
            
            mean = comparison[column].mean()
            std = comparison[column].std()
            
            # Flag devices with unusual patterns (>2 standard deviations)
            for idx, row in comparison.iterrows():
                if abs(row[column] - mean) > 2 * std:
                    unusual.append({
                        'device_ip': row['device_ip'],
                        'anomaly_type': column,
                        'value': row[column],
                        'mean': round(mean, 2),
                        'std_dev': round(std, 2),
                        'deviation_factor': round(abs(row[column] - mean) / std, 2),
                    })
        
        if unusual:
            unusual_df = pd.DataFrame(unusual).drop_duplicates(subset=['device_ip'])
            logger.warning(f"Identified {len(unusual_df)} devices with unusual behavior")
            return unusual_df
        
        return pd.DataFrame()
    
    def export_profiles(self, output_dir):
        """Export device behavioral profiles"""
        comparison = self.compare_devices()
        unusual = self.identify_unusual_behavior()
        
        comparison.to_csv(f'{output_dir}/device_behaviors.csv', index=False)
        
        if not unusual.empty:
            unusual.to_csv(f'{output_dir}/unusual_behaviors.csv', index=False)
        
        logger.info(f"Behavioral profiles exported to {output_dir}")


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
    
    # Create behavioral profiles
    profiler = BehavioralProfiler(features)
    
    print("\nDevice Behavior Comparison:")
    print(profiler.compare_devices())
    
    print("\nUnusual Behavior Detection:")
    print(profiler.identify_unusual_behavior())
