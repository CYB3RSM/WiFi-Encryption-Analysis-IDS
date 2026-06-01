"""
Module 8: Anomaly Detection (ML/DL)
Detects abnormal encrypted traffic spikes, exfiltration-like flows,
and suspicious behavioral patterns using Isolation Forest
"""

import pandas as pd
import numpy as np
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, f1_score

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """ML-based anomaly detection for network traffic"""

    def __init__(self, features_df):
        self.features = features_df.copy()
        self.model = None
        self.scaler = StandardScaler()
        self.anomaly_results = None
        self.feature_cols = [
            'packet_size', 'src_port', 'dst_port', 'encrypted_flag',
            'hour', 'protocol_num', 'size_anomaly_score'
        ]

    def _prepare_features(self):
        """Build ML feature matrix from available columns"""
        df = self.features.copy()
        available = [c for c in self.feature_cols if c in df.columns]

        # Add flow-level aggregate features
        flow_stats = df.groupby('src_ip').agg(
            flow_packet_count=('packet_size', 'count'),
            flow_total_bytes=('packet_size', 'sum'),
            flow_mean_size=('packet_size', 'mean'),
            flow_std_size=('packet_size', 'std'),
            flow_unique_dsts=('dst_ip', 'nunique'),
            flow_enc_ratio=('encrypted_flag', 'mean'),
        ).reset_index()
        flow_stats['flow_std_size'] = flow_stats['flow_std_size'].fillna(0)

        df = df.merge(flow_stats, on='src_ip', how='left')

        extra = ['flow_packet_count', 'flow_total_bytes', 'flow_mean_size',
                 'flow_std_size', 'flow_unique_dsts', 'flow_enc_ratio']
        available += [c for c in extra if c in df.columns]

        X = df[available].fillna(0)
        return X, df

    def inject_anomalies(self, anomaly_rate=0.03):
        """Inject synthetic anomalies for evaluation (ground truth labels)"""
        df = self.features.copy()
        n_anomalies = int(len(df) * anomaly_rate)
        idx = np.random.choice(df.index, n_anomalies, replace=False)
        df['is_anomaly'] = 0
        df.loc[idx, 'is_anomaly'] = 1
        # Make anomalies statistically distinct
        df.loc[idx, 'packet_size'] = np.random.randint(1200, 1500, n_anomalies)
        df.loc[idx, 'encrypted_flag'] = 1
        if 'hour' in df.columns:
            df.loc[idx, 'hour'] = np.random.choice([1, 2, 3, 23], n_anomalies)
        self.features = df
        logger.info(f"Injected {n_anomalies} anomalies ({anomaly_rate*100:.1f}%)")
        return df

    def train_isolation_forest(self, contamination=0.03, n_estimators=200):
        """Train Isolation Forest anomaly detection model"""
        X, df_enriched = self._prepare_features()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_scaled)

        scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)  # -1 anomaly, 1 normal

        df_enriched['anomaly_score'] = scores
        df_enriched['ml_anomaly'] = (predictions == -1).astype(int)
        self.anomaly_results = df_enriched

        n_detected = df_enriched['ml_anomaly'].sum()
        logger.info(f"Isolation Forest trained. Detected {n_detected} anomalies.")
        return df_enriched

    def rule_based_detection(self):
        """Rule-based detection for exfiltration and scanning patterns"""
        if self.anomaly_results is None:
            self.train_isolation_forest()

        df = self.anomaly_results.copy()
        df['rule_anomaly'] = 0
        df['rule_reason'] = ''

        # Rule 1: Large encrypted off-hours flows (exfiltration pattern)
        mask1 = (
            (df['packet_size'] > 1200) &
            (df['encrypted_flag'] == 1) &
            (df.get('hour', pd.Series(12, index=df.index)) < 6)
        )
        df.loc[mask1, 'rule_anomaly'] = 1
        df.loc[mask1, 'rule_reason'] = 'Large encrypted off-hours flow'

        # Rule 2: High destination fan-out (scanning)
        if 'flow_unique_dsts' in df.columns:
            mask2 = df['flow_unique_dsts'] > df['flow_unique_dsts'].quantile(0.95)
            df.loc[mask2, 'rule_anomaly'] = 1
            df.loc[mask2, 'rule_reason'] = df.loc[mask2, 'rule_reason'].apply(
                lambda x: x + '; Scanning pattern' if x else 'Scanning pattern'
            )

        # Rule 3: Risky ports with large payload
        risky_ports = [23, 21, 69, 161]
        if 'dst_port' in df.columns:
            mask3 = (df['dst_port'].isin(risky_ports)) & (df['packet_size'] > 500)
            df.loc[mask3, 'rule_anomaly'] = 1
            df.loc[mask3, 'rule_reason'] = df.loc[mask3, 'rule_reason'].apply(
                lambda x: x + '; Risky port with large payload' if x else 'Risky port with large payload'
            )

        df['combined_anomaly'] = ((df['ml_anomaly'] == 1) | (df['rule_anomaly'] == 1)).astype(int)
        self.anomaly_results = df

        rule_count = df['rule_anomaly'].sum()
        combined_count = df['combined_anomaly'].sum()
        logger.info(f"Rule-based: {rule_count} | Combined: {combined_count} anomalies")
        return df

    def evaluate_model(self):
        """Evaluate model if ground-truth labels available"""
        if self.anomaly_results is None:
            self.rule_based_detection()

        df = self.anomaly_results
        if 'is_anomaly' not in df.columns:
            logger.warning("No ground-truth labels. Run inject_anomalies() first.")
            return None

        y_true = df['is_anomaly']
        y_pred = df['ml_anomaly']

        report = classification_report(y_true, y_pred, target_names=['Normal', 'Anomaly'], output_dict=True)
        cm = confusion_matrix(y_true, y_pred)
        f1 = f1_score(y_true, y_pred)

        evaluation = {
            'classification_report': report,
            'confusion_matrix': cm.tolist(),
            'f1_score': round(f1, 4),
            'precision': round(report['Anomaly']['precision'], 4),
            'recall': round(report['Anomaly']['recall'], 4),
            'accuracy': round(report['accuracy'], 4),
            'total_anomalies_detected': int(y_pred.sum()),
            'total_actual_anomalies': int(y_true.sum()),
        }

        logger.info(f"Evaluation: F1={f1:.3f}, Precision={report['Anomaly']['precision']:.3f}, "
                    f"Recall={report['Anomaly']['recall']:.3f}")
        return evaluation

    def get_top_anomalies(self, n=20):
        """Return the most anomalous records"""
        if self.anomaly_results is None:
            self.rule_based_detection()
        df = self.anomaly_results
        return df.nsmallest(n, 'anomaly_score')[
            ['src_ip', 'dst_ip', 'dst_port', 'packet_size',
             'encrypted_flag', 'anomaly_score', 'ml_anomaly']
        ]

    def get_anomaly_summary(self):
        """Summary statistics for anomaly detection"""
        if self.anomaly_results is None:
            self.rule_based_detection()
        df = self.anomaly_results
        return {
            'total_packets': len(df),
            'ml_anomalies': int(df['ml_anomaly'].sum()),
            'rule_anomalies': int(df.get('rule_anomaly', pd.Series(0)).sum()),
            'combined_anomalies': int(df.get('combined_anomaly', df['ml_anomaly']).sum()),
            'anomaly_rate_pct': round(df['ml_anomaly'].mean() * 100, 2),
            'most_anomalous_src': df.loc[df['anomaly_score'].idxmin(), 'src_ip'] if len(df) > 0 else 'N/A',
        }

    def export_results(self, output_dir):
        """Export anomaly detection results"""
        if self.anomaly_results is None:
            self.rule_based_detection()
        df = self.anomaly_results
        anomalies = df[df['ml_anomaly'] == 1]
        anomalies.to_csv(f'{output_dir}/detected_anomalies.csv', index=False)
        df[['src_ip', 'dst_ip', 'packet_size', 'anomaly_score', 'ml_anomaly']].to_csv(
            f'{output_dir}/anomaly_scores.csv', index=False
        )
        logger.info(f"Anomaly results exported to {output_dir}")


if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/home/claude/ids_project/modules')
    from traffic_acquisition import TrafficAcquisition
    from packet_parser import PacketParser

    acq = TrafficAcquisition()
    data = acq.create_synthetic_dataset(2000)
    parser = PacketParser(data)
    features = parser.extract_all_features()

    detector = AnomalyDetector(features)
    detector.inject_anomalies(0.03)
    detector.rule_based_detection()
    eval_result = detector.evaluate_model()

    print("\nAnomaly Summary:", detector.get_anomaly_summary())
    if eval_result:
        print(f"F1-Score: {eval_result['f1_score']}, Accuracy: {eval_result['accuracy']}")
    print("\nTop Anomalies:")
    print(detector.get_top_anomalies(5))
