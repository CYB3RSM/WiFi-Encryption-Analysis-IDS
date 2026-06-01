"""
Module 2: Packet Parsing & Feature Extraction
Extracts metadata: IP, MAC, ports, protocols, packet size, timestamps
"""

import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)


class PacketParser:
    """Parses packets and extracts relevant features"""
    
    def __init__(self, raw_data):
        """
        Initialize packet parser
        
        Args:
            raw_data: DataFrame containing raw packet data
        """
        self.raw_data = raw_data.copy()
        self.features = None
        
    def extract_network_features(self):
        """Extract basic network layer features"""
        df = self.raw_data.copy()
        
        # Convert timestamp to datetime if not already
        if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Extract temporal features
        df['hour'] = df['timestamp'].dt.hour
        df['day'] = df['timestamp'].dt.day
        df['minute'] = df['timestamp'].dt.minute
        
        # Validate IP addresses
        df['src_ip_valid'] = df['src_ip'].apply(self._validate_ip)
        df['dst_ip_valid'] = df['dst_ip'].apply(self._validate_ip)
        
        logger.info("Network features extracted")
        return df
    
    def extract_transport_features(self, df):
        """Extract transport layer features"""
        # Protocol classification
        protocol_map = {
            'TCP': 6,
            'UDP': 17,
            'ICMP': 1,
            'DNS': 17  # DNS uses UDP typically
        }
        df['protocol_num'] = df['protocol'].map(protocol_map)
        
        # Port classification
        def classify_port(port):
            if port < 1024:
                return 'Well-Known'
            elif port < 49152:
                return 'Registered'
            else:
                return 'Dynamic'
        
        df['src_port_class'] = df['src_port'].apply(classify_port)
        df['dst_port_class'] = df['dst_port'].apply(classify_port)
        
        # Port risk assessment
        risky_ports = [23, 21, 69, 161, 162, 389]
        df['dst_port_risk'] = df['dst_port'].apply(lambda x: 'High' if x in risky_ports else 'Low')
        
        logger.info("Transport features extracted")
        return df
    
    def extract_payload_features(self, df):
        """Extract payload related features"""
        # Packet size statistics
        df['packet_size_class'] = pd.cut(
            df['packet_size'],
            bins=[0, 64, 128, 256, 512, 1500],
            labels=['Tiny', 'Small', 'Medium', 'Large', 'Jumbo']
        )
        
        # Calculate packet size anomaly score
        mean_size = df['packet_size'].mean()
        std_size = df['packet_size'].std()
        df['size_anomaly_score'] = np.abs((df['packet_size'] - mean_size) / std_size)
        
        logger.info("Payload features extracted")
        return df
    
    def extract_mac_features(self, df):
        """Extract MAC layer features"""
        # Validate MAC addresses
        df['src_mac_valid'] = df['src_mac'].apply(self._validate_mac)
        df['dst_mac_valid'] = df['dst_mac'].apply(self._validate_mac)
        
        # Check for broadcast MAC
        df['is_broadcast'] = df['dst_mac'].apply(lambda x: x == 'ff:ff:ff:ff:ff:ff')
        
        logger.info("MAC features extracted")
        return df
    
    def extract_all_features(self):
        """Extract all available features from packets"""
        df = self.extract_network_features()
        df = self.extract_transport_features(df)
        df = self.extract_payload_features(df)
        df = self.extract_mac_features(df)
        
        self.features = df
        logger.info(f"Total features extracted: {len(df.columns)}")
        return df
    
    @staticmethod
    def _validate_ip(ip):
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    @staticmethod
    def _validate_mac(mac):
        """Validate MAC address format"""
        try:
            parts = mac.split(':')
            if len(parts) != 6:
                return False
            return all(len(part) == 2 for part in parts)
        except:
            return False
    
    def get_feature_summary(self):
        """Get summary statistics of extracted features"""
        if self.features is None:
            self.extract_all_features()
        
        summary = {
            'total_packets': len(self.features),
            'unique_src_ips': self.features['src_ip'].nunique(),
            'unique_dst_ips': self.features['dst_ip'].nunique(),
            'unique_protocols': self.features['protocol'].nunique(),
            'avg_packet_size': self.features['packet_size'].mean(),
            'min_packet_size': self.features['packet_size'].min(),
            'max_packet_size': self.features['packet_size'].max(),
            'encrypted_packets': self.features['encrypted_flag'].sum(),
            'encryption_ratio': self.features['encrypted_flag'].mean(),
        }
        
        return summary
    
    def preprocess_data(self):
        """Perform data preprocessing and cleaning"""
        df = self.features.copy()
        
        # Handle missing values
        df = df.fillna('Unknown')
        
        # Remove invalid records
        df = df[df['src_ip_valid'] == True]
        df = df[df['dst_ip_valid'] == True]
        
        logger.info(f"Preprocessing complete. Remaining packets: {len(df)}")
        return df
    
    def get_features(self):
        """Return extracted features"""
        return self.features


if __name__ == "__main__":
    # Example usage
    import sys
    sys.path.insert(0, '/home/claude')
    from traffic_acquisition import TrafficAcquisition
    
    # Generate sample data
    acq = TrafficAcquisition()
    data = acq.create_synthetic_dataset(1000)
    
    # Parse and extract features
    parser = PacketParser(data)
    features = parser.extract_all_features()
    
    print("\nFeature Summary:")
    print(parser.get_feature_summary())
    
    print("\nFeature columns:")
    print(features.columns.tolist())
    
    print("\nSample extracted features:")
    print(features[['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_size', 'encrypted_flag']].head())
