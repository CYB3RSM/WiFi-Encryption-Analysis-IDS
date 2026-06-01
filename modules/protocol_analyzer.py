"""
Module 4: Protocol & Application Analysis
Analyzes DNS, HTTP, TLS handshake metadata
"""

import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)


class ProtocolAnalyzer:
    """Analyzes network protocols and application behavior"""
    
    def __init__(self, features_df):
        """
        Initialize protocol analyzer
        
        Args:
            features_df: DataFrame with extracted features
        """
        self.features = features_df.copy()
        self.protocol_stats = None
        self.dns_queries = None
        self.tls_handshakes = None
        
    def analyze_protocol_distribution(self):
        """Analyze protocol usage distribution"""
        protocol_counts = self.features['protocol'].value_counts()
        protocol_percentages = (protocol_counts / len(self.features) * 100).round(2)
        
        protocol_stats = pd.DataFrame({
            'Protocol': protocol_counts.index,
            'Count': protocol_counts.values,
            'Percentage': protocol_percentages.values
        })
        
        self.protocol_stats = protocol_stats
        logger.info(f"Analyzed {len(protocol_stats)} unique protocols")
        return protocol_stats
    
    def extract_dns_queries(self):
        """Extract DNS query information"""
        dns_traffic = self.features[
            (self.features['protocol'] == 'DNS') |
            (self.features['dst_port'] == 53)
        ].copy()
        
        if len(dns_traffic) == 0:
            logger.warning("No DNS traffic found")
            return pd.DataFrame()
        
        dns_queries = dns_traffic[[
            'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'packet_size', 'protocol'
        ]].copy()
        
        dns_queries['query_size'] = dns_queries['packet_size']
        dns_queries['response_indicator'] = (dns_queries['src_port'] == 53).astype(int)
        
        self.dns_queries = dns_queries
        logger.info(f"Extracted {len(dns_queries)} DNS queries/responses")
        return dns_queries
    
    def extract_http_metadata(self):
        """Extract HTTP metadata (non-encrypted traffic on port 80)"""
        http_traffic = self.features[
            (self.features['encrypted_flag'] == 0) &
            (self.features['dst_port'].isin([80, 8080]))
        ].copy()
        
        if len(http_traffic) == 0:
            logger.warning("No HTTP traffic found")
            return pd.DataFrame()
        
        http_metadata = http_traffic[[
            'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'packet_size', 'protocol'
        ]].copy()
        
        http_metadata['request_size_class'] = pd.cut(
            http_metadata['packet_size'],
            bins=[0, 64, 256, 1024, 1500],
            labels=['Header', 'Small', 'Medium', 'Large']
        )
        
        logger.info(f"Extracted {len(http_metadata)} HTTP transactions")
        return http_metadata
    
    def analyze_tls_handshakes(self):
        """Analyze TLS handshake metadata"""
        # Filter encrypted traffic
        encrypted_traffic = self.features[self.features['encrypted_flag'] == 1].copy()
        
        if len(encrypted_traffic) == 0:
            logger.warning("No encrypted traffic found")
            return pd.DataFrame()
        
        # Group by connection (src_ip + dst_ip + dst_port)
        encrypted_traffic['connection_id'] = (
            encrypted_traffic['src_ip'] + '_' +
            encrypted_traffic['dst_ip'] + '_' +
            encrypted_traffic['dst_port'].astype(str)
        )
        
        handshake_analysis = []
        
        for conn_id, group in encrypted_traffic.groupby('connection_id'):
            analysis = {
                'connection_id': conn_id,
                'src_ip': group['src_ip'].iloc[0],
                'dst_ip': group['dst_ip'].iloc[0],
                'dst_port': group['dst_port'].iloc[0],
                'tls_version': group['tls_version'].iloc[0],
                'cipher_suite': group['cipher_suite'].iloc[0],
                'key_exchange': group['key_exchange'].iloc[0],
                'encryption_strength': group['encryption_strength'].iloc[0],
                'total_packets': len(group),
                'total_bytes': group['packet_size'].sum(),
                'first_seen': group['timestamp'].min(),
                'last_seen': group['timestamp'].max(),
                'duration_seconds': (group['timestamp'].max() - group['timestamp'].min()).total_seconds(),
            }
            
            handshake_analysis.append(analysis)
        
        self.tls_handshakes = pd.DataFrame(handshake_analysis)
        logger.info(f"Analyzed {len(handshake_analysis)} TLS connections")
        return self.tls_handshakes
    
    def get_port_analysis(self):
        """Analyze port usage and services"""
        port_analysis = self.features.groupby('dst_port').agg({
            'src_ip': 'nunique',  # Unique sources
            'packet_size': ['count', 'sum', 'mean'],
            'encrypted_flag': 'sum'
        }).round(2)
        
        port_analysis.columns = ['unique_sources', 'packet_count', 'total_bytes', 'avg_packet_size', 'encrypted_packets']
        port_analysis = port_analysis.sort_values('packet_count', ascending=False)
        
        logger.info(f"Analyzed {len(port_analysis)} unique destination ports")
        return port_analysis
    
    def get_service_mapping(self):
        """Map ports to known services"""
        service_map = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            587: 'SMTP-TLS',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
        }
        
        return service_map
    
    def get_protocol_security_summary(self):
        """Get security summary of protocol usage"""
        if self.protocol_stats is None:
            self.analyze_protocol_distribution()
        
        encrypted_count = self.features['encrypted_flag'].sum()
        total_count = len(self.features)
        
        summary = {
            'total_packets': total_count,
            'encrypted_packets': encrypted_count,
            'unencrypted_packets': total_count - encrypted_count,
            'encryption_percentage': round((encrypted_count / total_count * 100), 2),
            'protocols_used': self.features['protocol'].nunique(),
            'unique_ports': self.features['dst_port'].nunique(),
        }
        
        return summary
    
    def export_analysis(self, output_dir):
        """Export all analysis results"""
        if self.protocol_stats is not None:
            self.protocol_stats.to_csv(f'{output_dir}/protocol_stats.csv', index=False)
        
        if self.dns_queries is not None and len(self.dns_queries) > 0:
            self.dns_queries.to_csv(f'{output_dir}/dns_queries.csv', index=False)
        
        if self.tls_handshakes is not None and len(self.tls_handshakes) > 0:
            self.tls_handshakes.to_csv(f'{output_dir}/tls_handshakes.csv', index=False)
        
        logger.info(f"Analysis exported to {output_dir}")


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
    
    # Analyze protocols
    analyzer = ProtocolAnalyzer(features)
    
    print("\nProtocol Distribution:")
    print(analyzer.analyze_protocol_distribution())
    
    print("\nTLS Handshakes:")
    print(analyzer.analyze_tls_handshakes().head())
    
    print("\nSecurity Summary:")
    print(analyzer.get_protocol_security_summary())
