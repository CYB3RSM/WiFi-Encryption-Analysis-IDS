"""
Module 6: Encryption Scheme & Strength Analysis
Evaluates TLS version, cipher suites, and key exchange algorithms
"""

import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)


class EncryptionStrengthAnalyzer:
    """Analyzes and evaluates encryption strength"""
    
    def __init__(self, features_df):
        """
        Initialize encryption strength analyzer
        
        Args:
            features_df: DataFrame with extracted features
        """
        self.features = features_df.copy()
        self.tls_version_scores = self._initialize_tls_scores()
        self.cipher_suite_scores = self._initialize_cipher_scores()
        self.key_exchange_scores = self._initialize_key_exchange_scores()
        
    def _initialize_tls_scores(self):
        """Initialize TLS version security scores"""
        return {
            'TLS 1.3': {'score': 100, 'status': 'Strong', 'supported': True},
            'TLS 1.2': {'score': 85, 'status': 'Strong', 'supported': True},
            'TLS 1.1': {'score': 40, 'status': 'Weak', 'supported': False},
            'TLS 1.0': {'score': 30, 'status': 'Weak', 'supported': False},
            'SSL 3.0': {'score': 10, 'status': 'Deprecated', 'supported': False},
            'SSL 2.0': {'score': 0, 'status': 'Deprecated', 'supported': False},
            'None': {'score': 0, 'status': 'Unencrypted', 'supported': None},
        }
    
    def _initialize_cipher_scores(self):
        """Initialize cipher suite security scores"""
        return {
            # Modern ciphers
            'TLS_AES_256_GCM_SHA384': {'score': 100, 'strength': 'Strong', 'key_bits': 256},
            'TLS_CHACHA20_POLY1305_SHA256': {'score': 95, 'strength': 'Strong', 'key_bits': 256},
            'ECDHE-RSA-AES256-GCM-SHA384': {'score': 95, 'strength': 'Strong', 'key_bits': 256},
            'ECDHE-RSA-AES128-GCM-SHA256': {'score': 90, 'strength': 'Strong', 'key_bits': 128},
            
            # Legacy ciphers
            'RSA-AES256-SHA256': {'score': 65, 'strength': 'Weak', 'key_bits': 256},
            'RSA-AES128-SHA256': {'score': 60, 'strength': 'Weak', 'key_bits': 128},
            'AES128-SHA': {'score': 50, 'strength': 'Weak', 'key_bits': 128},
            'DES-CBC3-SHA': {'score': 30, 'strength': 'Deprecated', 'key_bits': 168},
            'RC4-SHA': {'score': 20, 'strength': 'Deprecated', 'key_bits': 128},
            
            'None': {'score': 0, 'strength': 'None', 'key_bits': 0},
        }
    
    def _initialize_key_exchange_scores(self):
        """Initialize key exchange algorithm scores"""
        return {
            'ECDHE': {'score': 95, 'strength': 'Strong', 'perfect_forward_secrecy': True},
            'DHE': {'score': 85, 'strength': 'Strong', 'perfect_forward_secrecy': True},
            'ECDH': {'score': 75, 'strength': 'Good', 'perfect_forward_secrecy': False},
            'DH': {'score': 70, 'strength': 'Good', 'perfect_forward_secrecy': False},
            'RSA': {'score': 50, 'strength': 'Weak', 'perfect_forward_secrecy': False},
            'None': {'score': 0, 'strength': 'None', 'perfect_forward_secrecy': False},
        }
    
    def analyze_tls_versions(self):
        """Analyze TLS version distribution"""
        if 'tls_version' not in self.features.columns:
            return pd.DataFrame()
        
        encrypted = self.features[self.features['encrypted_flag'] == 1]
        
        if len(encrypted) == 0:
            return pd.DataFrame()
        
        tls_dist = encrypted['tls_version'].value_counts()
        
        analysis = []
        for tls_version, count in tls_dist.items():
            score_info = self.tls_version_scores.get(tls_version, {'score': 0, 'status': 'Unknown'})
            
            analysis.append({
                'tls_version': tls_version,
                'packet_count': count,
                'percentage': round((count / len(encrypted) * 100), 2),
                'security_score': score_info['score'],
                'status': score_info['status'],
            })
        
        result_df = pd.DataFrame(analysis).sort_values('packet_count', ascending=False)
        logger.info(f"Analyzed {len(result_df)} TLS versions")
        return result_df
    
    def analyze_cipher_suites(self):
        """Analyze cipher suite distribution"""
        if 'cipher_suite' not in self.features.columns:
            return pd.DataFrame()
        
        encrypted = self.features[self.features['encrypted_flag'] == 1]
        
        if len(encrypted) == 0:
            return pd.DataFrame()
        
        cipher_dist = encrypted['cipher_suite'].value_counts()
        
        analysis = []
        for cipher_suite, count in cipher_dist.items():
            score_info = self.cipher_suite_scores.get(cipher_suite, {'score': 0, 'strength': 'Unknown', 'key_bits': 0})
            
            analysis.append({
                'cipher_suite': cipher_suite,
                'packet_count': count,
                'percentage': round((count / len(encrypted) * 100), 2),
                'security_score': score_info['score'],
                'strength': score_info['strength'],
                'key_bits': score_info['key_bits'],
            })
        
        result_df = pd.DataFrame(analysis).sort_values('packet_count', ascending=False)
        logger.info(f"Analyzed {len(result_df)} cipher suites")
        return result_df
    
    def analyze_key_exchange(self):
        """Analyze key exchange algorithm distribution"""
        if 'key_exchange' not in self.features.columns:
            return pd.DataFrame()
        
        encrypted = self.features[self.features['encrypted_flag'] == 1]
        
        if len(encrypted) == 0:
            return pd.DataFrame()
        
        kex_dist = encrypted['key_exchange'].value_counts()
        
        analysis = []
        for kex, count in kex_dist.items():
            score_info = self.key_exchange_scores.get(kex, {'score': 0, 'strength': 'Unknown'})
            
            analysis.append({
                'key_exchange': kex,
                'packet_count': count,
                'percentage': round((count / len(encrypted) * 100), 2),
                'security_score': score_info['score'],
                'strength': score_info['strength'],
                'pfs_enabled': score_info.get('perfect_forward_secrecy', False),
            })
        
        result_df = pd.DataFrame(analysis).sort_values('packet_count', ascending=False)
        logger.info(f"Analyzed {len(result_df)} key exchange algorithms")
        return result_df
    
    def calculate_overall_strength(self):
        """Calculate overall encryption strength score"""
        encrypted = self.features[self.features['encrypted_flag'] == 1]
        
        if len(encrypted) == 0:
            return {'overall_score': 0, 'message': 'No encrypted traffic detected'}
        
        # Calculate average scores
        tls_scores = []
        cipher_scores = []
        kex_scores = []
        
        for idx, row in encrypted.iterrows():
            tls_version = str(row.get('tls_version', 'None'))
            cipher = str(row.get('cipher_suite', 'None'))
            kex = str(row.get('key_exchange', 'None'))
            
            tls_score = self.tls_version_scores.get(tls_version, {}).get('score', 0)
            cipher_score = self.cipher_suite_scores.get(cipher, {}).get('score', 0)
            kex_score = self.key_exchange_scores.get(kex, {}).get('score', 0)
            
            tls_scores.append(tls_score)
            cipher_scores.append(cipher_score)
            kex_scores.append(kex_score)
        
        # Weighted average
        avg_tls = np.mean(tls_scores) * 0.4
        avg_cipher = np.mean(cipher_scores) * 0.35
        avg_kex = np.mean(kex_scores) * 0.25
        
        overall_score = round(avg_tls + avg_cipher + avg_kex, 2)
        
        # Determine rating
        if overall_score >= 80:
            rating = 'Strong'
        elif overall_score >= 60:
            rating = 'Good'
        elif overall_score >= 40:
            rating = 'Weak'
        else:
            rating = 'Critical'
        
        return {
            'overall_score': overall_score,
            'rating': rating,
            'tls_avg_score': round(np.mean(tls_scores), 2),
            'cipher_avg_score': round(np.mean(cipher_scores), 2),
            'kex_avg_score': round(np.mean(kex_scores), 2),
            'encrypted_packets': len(encrypted),
        }
    
    def identify_weak_encryption_connections(self):
        """Identify connections with weak encryption"""
        encrypted = self.features[self.features['encrypted_flag'] == 1]
        
        weak_connections = []
        
        for idx, row in encrypted.iterrows():
            tls_version = str(row.get('tls_version', 'None'))
            cipher = str(row.get('cipher_suite', 'None'))
            
            tls_score = self.tls_version_scores.get(tls_version, {}).get('score', 100)
            cipher_score = self.cipher_suite_scores.get(cipher, {}).get('score', 100)
            
            # Flag if any component is weak
            if tls_score < 50 or cipher_score < 50:
                weak_connections.append({
                    'src_ip': row['src_ip'],
                    'dst_ip': row['dst_ip'],
                    'dst_port': row['dst_port'],
                    'tls_version': tls_version,
                    'cipher_suite': cipher,
                    'tls_score': tls_score,
                    'cipher_score': cipher_score,
                    'risk_level': 'High' if tls_score < 30 or cipher_score < 30 else 'Medium',
                })
        
        if len(weak_connections) > 0:
            result_df = pd.DataFrame(weak_connections)
            logger.warning(f"Identified {len(result_df)} weak encryption connections")
            return result_df
        
        return pd.DataFrame()
    
    def export_strength_analysis(self, output_dir):
        """Export all strength analysis results"""
        tls_analysis = self.analyze_tls_versions()
        cipher_analysis = self.analyze_cipher_suites()
        kex_analysis = self.analyze_key_exchange()
        weak_analysis = self.identify_weak_encryption_connections()
        overall = self.calculate_overall_strength()
        
        tls_analysis.to_csv(f'{output_dir}/tls_versions.csv', index=False)
        cipher_analysis.to_csv(f'{output_dir}/cipher_suites.csv', index=False)
        kex_analysis.to_csv(f'{output_dir}/key_exchange.csv', index=False)
        
        if len(weak_analysis) > 0:
            weak_analysis.to_csv(f'{output_dir}/weak_connections.csv', index=False)
        
        # Export overall score
        with open(f'{output_dir}/overall_score.txt', 'w') as f:
            for key, value in overall.items():
                f.write(f"{key}: {value}\n")
        
        logger.info(f"Strength analysis exported to {output_dir}")


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
    
    # Analyze encryption strength
    analyzer = EncryptionStrengthAnalyzer(features)
    
    print("\nTLS Versions:")
    print(analyzer.analyze_tls_versions())
    
    print("\nCipher Suites:")
    print(analyzer.analyze_cipher_suites())
    
    print("\nKey Exchange:")
    print(analyzer.analyze_key_exchange())
    
    print("\nOverall Strength:")
    print(analyzer.calculate_overall_strength())
