"""
Module 5: Encryption Detection & Classification
Detects and classifies encrypted traffic (TLS, SSL, QUIC, VPN)
"""

import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)


class EncryptionDetector:
    """Detects and classifies encrypted network traffic"""
    
    def __init__(self, features_df):
        """
        Initialize encryption detector
        
        Args:
            features_df: DataFrame with extracted features
        """
        self.features = features_df.copy()
        self.encrypted_traffic = None
        self.encryption_summary = None
        
    def detect_encrypted_traffic(self):
        """Detect encrypted vs unencrypted traffic"""
        # Initialize encrypted_flag if not present
        if 'encrypted_flag' not in self.features.columns:
            self.features['encrypted_flag'] = self._infer_encryption_from_ports()
        
        encrypted = self.features[self.features['encrypted_flag'] == 1]
        unencrypted = self.features[self.features['encrypted_flag'] == 0]
        
        detection_result = {
            'total_packets': len(self.features),
            'encrypted_packets': len(encrypted),
            'unencrypted_packets': len(unencrypted),
            'encryption_percentage': round((len(encrypted) / len(self.features) * 100), 2),
            'encrypted_bytes': encrypted['packet_size'].sum() if len(encrypted) > 0 else 0,
            'unencrypted_bytes': unencrypted['packet_size'].sum() if len(unencrypted) > 0 else 0,
        }
        
        self.encrypted_traffic = encrypted
        logger.info(f"Detected {len(encrypted)} encrypted packets ({detection_result['encryption_percentage']}%)")
        return detection_result
    
    def classify_encryption_protocols(self):
        """Classify encryption protocols (TLS, SSL, QUIC, VPN)"""
        if self.encrypted_traffic is None:
            self.detect_encrypted_traffic()
        
        classification = {
            'TLS': 0,
            'SSL': 0,
            'QUIC': 0,
            'VPN': 0,
            'Unknown': 0
        }
        
        for idx, row in self.encrypted_traffic.iterrows():
            protocol = self._classify_protocol(row)
            classification[protocol] += 1
        
        # Convert to percentage
        total = sum(classification.values())
        if total > 0:
            classification = {k: round((v/total*100), 2) for k, v in classification.items()}
        
        logger.info(f"Classified encryption protocols: {classification}")
        return classification
    
    def _classify_protocol(self, row):
        """Classify encryption protocol for a single connection"""
        tls_version = row.get('tls_version', 'None')
        dst_port = row['dst_port']
        
        # TLS/SSL detection
        if 'TLS' in str(tls_version):
            return 'TLS'
        elif 'SSL' in str(tls_version):
            return 'SSL'
        
        # Port-based classification
        if dst_port in [443, 8443]:
            return 'TLS'  # HTTPS
        elif dst_port in [993, 995]:
            return 'TLS'  # IMAPS, POP3S
        elif dst_port in [465, 587]:
            return 'TLS'  # SMTPS
        elif dst_port in [989, 990]:
            return 'TLS'  # FTPS
        elif dst_port == 1194:
            return 'VPN'  # OpenVPN
        elif dst_port == 500 or dst_port == 4500:
            return 'VPN'  # IPSec
        elif dst_port == 1723:
            return 'VPN'  # PPTP
        
        return 'Unknown'
    
    def _infer_encryption_from_ports(self):
        """Infer encryption status from port numbers"""
        encrypted_ports = [443, 465, 587, 993, 995, 989, 990, 8443, 1194, 500, 4500, 1723]
        return self.features['dst_port'].isin(encrypted_ports).astype(int)
    
    def analyze_encryption_by_device(self):
        """Analyze encryption usage per device"""
        if self.encrypted_traffic is None:
            self.detect_encrypted_traffic()
        
        device_encryption = self.features.groupby('src_ip').agg({
            'encrypted_flag': ['sum', 'count', 'mean']
        }).round(3)
        
        device_encryption.columns = ['encrypted_packets', 'total_packets', 'encryption_ratio']
        device_encryption = device_encryption.reset_index()
        device_encryption.columns = ['device_ip', 'encrypted_packets', 'total_packets', 'encryption_ratio']
        
        logger.info(f"Analyzed encryption for {len(device_encryption)} devices")
        return device_encryption
    
    def analyze_encryption_by_destination(self):
        """Analyze encryption usage per destination"""
        dest_encryption = self.features.groupby('dst_ip').agg({
            'encrypted_flag': ['sum', 'count', 'mean']
        }).round(3)
        
        dest_encryption.columns = ['encrypted_packets', 'total_packets', 'encryption_ratio']
        dest_encryption = dest_encryption.reset_index()
        dest_encryption.columns = ['destination_ip', 'encrypted_packets', 'total_packets', 'encryption_ratio']
        
        logger.info(f"Analyzed encryption for {len(dest_encryption)} destinations")
        return dest_encryption
    
    def get_encryption_summary(self):
        """Get comprehensive encryption summary"""
        if self.encrypted_traffic is None:
            self.detect_encrypted_traffic()
        
        encrypted = self.encrypted_traffic
        
        summary = {
            'total_encrypted_packets': len(encrypted),
            'encryption_percentage': round((len(encrypted) / len(self.features) * 100), 2),
            'unique_encrypted_sources': encrypted['src_ip'].nunique(),
            'unique_encrypted_destinations': encrypted['dst_ip'].nunique(),
            'encrypted_port_count': encrypted['dst_port'].nunique(),
            'most_common_encrypted_port': encrypted['dst_port'].mode().values[0] if len(encrypted) > 0 else 'N/A',
            'protocols_used': encrypted['protocol'].unique().tolist(),
        }
        
        # TLS version distribution
        if 'tls_version' in encrypted.columns:
            summary['tls_versions'] = encrypted['tls_version'].value_counts().to_dict()
        
        # Cipher suite distribution
        if 'cipher_suite' in encrypted.columns:
            summary['cipher_suites'] = encrypted['cipher_suite'].value_counts().to_dict()
        
        return summary
    
    def detect_weak_encryption(self):
        """Detect weak or deprecated encryption"""
        if self.encrypted_traffic is None:
            self.detect_encrypted_traffic()
        
        weak_tls = ['SSL 3.0', 'TLS 1.0', 'TLS 1.1']
        weak_ciphers = ['RSA-AES128-SHA256', 'DES', 'RC4', 'MD5']
        
        weak_encryption = []
        
        for idx, row in self.encrypted_traffic.iterrows():
            tls_version = str(row.get('tls_version', ''))
            cipher_suite = str(row.get('cipher_suite', ''))
            
            if any(weak in tls_version for weak in weak_tls) or any(weak in cipher_suite for weak in weak_ciphers):
                weak_encryption.append(row)
        
        weak_df = pd.DataFrame(weak_encryption)
        logger.warning(f"Detected {len(weak_df)} weak encryption connections")
        return weak_df
    
    def export_encryption_analysis(self, output_dir):
        """Export encryption analysis results"""
        device_enc = self.analyze_encryption_by_device()
        dest_enc = self.analyze_encryption_by_destination()
        weak_enc = self.detect_weak_encryption()
        
        device_enc.to_csv(f'{output_dir}/device_encryption.csv', index=False)
        dest_enc.to_csv(f'{output_dir}/destination_encryption.csv', index=False)
        
        if len(weak_enc) > 0:
            weak_enc.to_csv(f'{output_dir}/weak_encryption.csv', index=False)
        
        logger.info(f"Encryption analysis exported to {output_dir}")


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
    
    # Detect encryption
    detector = EncryptionDetector(features)
    
    print("\nEncryption Detection:")
    print(detector.detect_encrypted_traffic())
    
    print("\nEncryption Protocols:")
    print(detector.classify_encryption_protocols())
    
    print("\nEncryption Summary:")
    print(detector.get_encryption_summary())
    
    print("\nWeak Encryption Connections:")
    print(detector.detect_weak_encryption().head())
