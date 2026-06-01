"""
Module 1: Traffic Acquisition
WiFi Traffic Monitoring and Encryption Analysis System
Acquires PCAP data or imports from dataset
"""

import os
import json
import pandas as pd
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TrafficAcquisition:
    """Handles traffic data acquisition from PCAP or CSV datasets"""
    
    def __init__(self, data_source=None, source_type='csv'):
        """
        Initialize traffic acquisition module
        
        Args:
            data_source: Path to PCAP file or CSV dataset
            source_type: 'pcap' or 'csv'
        """
        self.data_source = data_source
        self.source_type = source_type
        self.packets = []
        self.raw_data = None
        
    def load_dataset_from_csv(self, csv_path):
        """Load traffic data from CSV file"""
        try:
            self.raw_data = pd.read_csv(csv_path)
            logger.info(f"Loaded {len(self.raw_data)} packets from {csv_path}")
            return self.raw_data
        except Exception as e:
            logger.error(f"Error loading CSV: {str(e)}")
            return None
    
    def load_dataset_from_pcap(self, pcap_path):
        """Load traffic data from PCAP file using scapy"""
        try:
            from scapy.all import rdpcap
            packets = rdpcap(pcap_path)
            logger.info(f"Loaded {len(packets)} packets from {pcap_path}")
            return packets
        except Exception as e:
            logger.error(f"Error loading PCAP: {str(e)}")
            return None
    
    def create_synthetic_dataset(self, num_packets=5000):
        """Generate synthetic network traffic dataset for lab environment"""
        import numpy as np
        
        data = {
            'timestamp': pd.date_range(start='2026-01-01', periods=num_packets, freq='100ms'),
            'src_ip': np.random.choice(['192.168.1.100', '192.168.1.101', '192.168.1.102', '192.168.1.103', '10.0.0.50'], num_packets),
            'dst_ip': np.random.choice(['8.8.8.8', '1.1.1.1', '142.251.41.14', '93.184.216.34', '52.84.49.130'], num_packets),
            'src_port': np.random.randint(49152, 65535, num_packets),
            'dst_port': np.random.choice([80, 443, 53, 22, 25, 587, 993, 995, 123, 161], num_packets),
            'protocol': np.random.choice(['TCP', 'UDP', 'ICMP', 'DNS'], num_packets),
            'packet_size': np.random.randint(40, 1500, num_packets),
            'src_mac': np.random.choice(['00:11:22:33:44:55', '00:11:22:33:44:56', '00:11:22:33:44:57'], num_packets),
            'dst_mac': np.random.choice(['ff:ff:ff:ff:ff:ff', '08:00:27:00:00:00'], num_packets),
        }
        
        df = pd.DataFrame(data)
        
        # Add encryption indicators based on port
        df['encrypted_flag'] = df['dst_port'].apply(
            lambda x: 1 if x in [443, 993, 995, 8443] else 0
        )
        
        # Add TLS version for encrypted traffic
        df['tls_version'] = df['encrypted_flag'].apply(
            lambda x: np.random.choice(['TLS 1.2', 'TLS 1.3', 'SSL 3.0', 'None'], p=[0.4, 0.5, 0.05, 0.05]) if x == 1 else 'None'
        )
        
        # Add cipher suites
        cipher_suites = [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'RSA-AES128-SHA256',
            'None'
        ]
        df['cipher_suite'] = df['encrypted_flag'].apply(
            lambda x: np.random.choice(cipher_suites) if x == 1 else 'None'
        )
        
        # Add key exchange
        df['key_exchange'] = df['encrypted_flag'].apply(
            lambda x: np.random.choice(['ECDHE', 'RSA', 'DHE', 'None']) if x == 1 else 'None'
        )
        
        # Add encryption strength classification
        strength_map = {
            'TLS_AES_256_GCM_SHA384': 'Strong',
            'TLS_CHACHA20_POLY1305_SHA256': 'Strong',
            'ECDHE-RSA-AES128-GCM-SHA256': 'Strong',
            'RSA-AES128-SHA256': 'Weak',
            'None': 'None'
        }
        df['encryption_strength'] = df['cipher_suite'].map(strength_map)
        
        self.raw_data = df
        logger.info(f"Generated synthetic dataset with {num_packets} packets")
        return df
    
    def export_dataset(self, output_path):
        """Export dataset to CSV"""
        try:
            self.raw_data.to_csv(output_path, index=False)
            logger.info(f"Dataset exported to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting dataset: {str(e)}")
            return False
    
    def get_packets(self):
        """Return loaded packets"""
        return self.raw_data
    
    def get_packet_count(self):
        """Return total number of packets"""
        if self.raw_data is not None:
            return len(self.raw_data)
        return 0


if __name__ == "__main__":
    # Example usage
    acq = TrafficAcquisition()
    
    # Generate synthetic dataset
    dataset = acq.create_synthetic_dataset(num_packets=5000)
    print(f"\nDataset shape: {dataset.shape}")
    print(f"\nFirst 5 packets:")
    print(dataset.head())
    
    # Export dataset
    acq.export_dataset('/mnt/user-data/outputs/network_traffic.csv')
