import os.path


class Setting:
    PROJECT_DIR = os.path.dirname(__file__)
    MODEL_DIR = os.path.join(PROJECT_DIR, 'new_models')
    DATA_DIR = os.path.join(PROJECT_DIR, 'data')

    AE_MODEL = os.path.join(MODEL_DIR, 'ae')
    OUTLIER_PERCENTAGE = os.path.join(MODEL_DIR, 'outliers_percentage.pkl')
    SCALER_MODEL = os.path.join(MODEL_DIR, 'scaler.pkl')
    SOM_MODEL = os.path.join(MODEL_DIR, 'som.pkl')
    WINMAP_MODEL = os.path.join(MODEL_DIR, 'winmap.pkl')

    SELECTED_COLUMNS = ["Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets","Fwd Packet Length Max", "Fwd Packet Length Min","Fwd Packet Length Mean", "Fwd Packet Length Std","Bwd Packet Length Max", "Bwd Packet Length Min","Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s","Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max","Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std","Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean","Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags","Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length","Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s","Min Packet Length", "Max Packet Length", "Packet Length Mean","Packet Length Std", "Packet Length Variance", "FIN Flag Count","SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count","URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio","Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size","Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate","Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate","Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets","Subflow Bwd Bytes", "Init_Win_bytes_forward","Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward","Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean","Idle Std", "Idle Max", "Idle Min", "Label"]
    SELECTED_COLUMNS_2 = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet", "Total Length of Bwd Packet", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWR Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Fwd Segment Size Avg", "Bwd Segment Size Avg", "Fwd Bytes/Bulk Avg", "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg", "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes", "FWD Init Win Bytes", "Bwd Init Win Bytes", "Fwd Act Data Pkts", "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min", "Label"]    
    SELECTED_COLUMNS_3 = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std", "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std", "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Len", "Bwd Header Len", "Fwd Pkts/s", "Bwd Pkts/s", "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var", "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt", "Down/Up Ratio", "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg", "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg", "Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts", "Subflow Bwd Byts", "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Act Data Pkts", "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min", "Label"]    

    ATTACK_SAMPLE_SQL = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp", "Flow Duration", "attack_type"]

    SELECTED_COLUMNS_SQL = ["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Timestamp", "Flow Duration", "attack_type"]
    SELECTED_COLUMNS_SQL_DB_LABEL = ["src_ip", "dst_ip", "src_ip", "src_port", "protocol", "timestamp", "flow_duration", "attack_type"]
    
class Config:
    MYSQL_URI = 'mysql+pymysql://root:Gsm%402022@127.0.0.1:3306/gsm'
    REDIS_HOST = 'localhost'
    REDIS_HOST_DOCKER = 'gsm-redis'
    REDIS_PORT = 6379
    REDIS_DB = 0
    
if __name__ == '__main__':
    print(Setting.PROJECT_DIR)
