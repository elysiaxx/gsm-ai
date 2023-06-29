import os.path
import os
import redis
import json

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import classification_report
from sklearn.preprocessing import normalize
from tensorflow.keras.models import load_model
from sqlalchemy import create_engine

from config import Setting, Config
from handler import insert_ai_events


def _som_classify(som, winmap, data):  # ,
    default_class = np.sum(list(winmap.values())).most_common()[0][0]
    result = []
    for d in data:
        win_position = som.winner(d)
        if win_position in winmap:
            result.append(winmap[win_position].most_common()[0][0])
        else:
            result.append(default_class)
    return result


def detection(scaler, som, encoder, outliers_percentage, winmap, df):
    if df is None or not isinstance(df, pd.DataFrame):
        return None, "Data is None or not an instance of data frame"
    try:
        df_selected = df[Setting.SELECTED_COLUMNS]
        target = df_selected.Label
        data = df_selected.drop(['Label'], axis=1)
        
        data = scaler.transform(data)
        data = encoder.predict(data)
        data = normalize(data)
        # 2 label
        # 1 - benign; 2 - attack
        y_test = [i if i == 1 else 2 for i in target]
        y_pred = _som_classify(som=som, winmap=winmap, data=data)  # , X_train=X_train, y_train=y_train)
        # chuyen doi label cho y_pred
        # y_pred = [i if i == 1 else 2 for i in y_pred]
        return y_pred, None
    except Exception as e:
        return None, e.__str__()

def process_file(filename):
    try:
        fr = open(filename, 'r')
        lines = fr.readlines()
        fr.close()
        
        indices = [i for i, x in enumerate(lines[1:]) if x == lines[0]]
        for ind in indices[::-1]:
            lines.pop(ind + 1)
            
        fw = open(filename, 'w')
        fw.writelines(lines)
        fw.close()
    except Exception as e:
        print(e.__str__())
        
        
if __name__ == '__main__':
        
    engine = create_engine(Config.MYSQL_URI, echo=False)
    
    r = redis.Redis(host=Config.REDIS_HOST, port=Config.REDIS_PORT, db=Config.REDIS_DB)
    
    p = r.pubsub(ignore_subscribe_messages=True)
    
    p.subscribe('watch_new_file_service')
    
    scaler = joblib.load(Setting.SCALER_MODEL)
    encoder = load_model(Setting.AE_MODEL)
    som = joblib.load(Setting.SOM_MODEL)
    outliers_percentage = joblib.load(Setting.OUTLIER_PERCENTAGE)
    winmap = joblib.load(Setting.WINMAP_MODEL)
    
    for message in p.listen():
        try:
            data = json.loads(message['data'].decode('utf-8'))
            
            if "path" not in data:
                continue
            if not os.path.exists(data['path']):
                print("File {0} isn't exist!".format(data['path']))
                continue
            
            print("Reading {0} ...".format(data['path']))
            df_data = pd.read_csv(data['path'])
            df = df_data[Setting.SELECTED_COLUMNS_2]
            
            df_detect = df.rename(columns={
                "Total Fwd Packet": "Total Fwd Packets",
                "Total Bwd packets": "Total Backward Packets",
                "Total Length of Fwd Packet": "Total Length of Fwd Packets",
                
                "Total Length of Bwd Packet" : "Total Length of Bwd Packets",
                "Packet Length Min": "Min Packet Length",
                "Packet Length Max": "Max Packet Length",
                
                "CWR Flag Count": "CWE Flag Count",
                "Fwd Segment Size Avg": "Avg Fwd Segment Size",
                "Bwd Segment Size Avg": "Avg Bwd Segment Size",
                
                "Fwd Bytes/Bulk Avg": "Fwd Avg Bytes/Bulk",
                "Fwd Packet/Bulk Avg": "Fwd Avg Packets/Bulk",
                "Fwd Bulk Rate Avg": "Fwd Avg Bulk Rate",
                
                "Bwd Bytes/Bulk Avg": "Bwd Avg Bytes/Bulk",
                "Bwd Packet/Bulk Avg": "Bwd Avg Packets/Bulk",
                "Bwd Bulk Rate Avg": "Bwd Avg Bulk Rate",
                "FWD Init Win Bytes": "Init_Win_bytes_forward",
                
                "Bwd Init Win Bytes": "Init_Win_bytes_backward",
                "Fwd Act Data Pkts": "act_data_pkt_fwd",
                "Fwd Seg Size Min": "min_seg_size_forward"
            })
            
            df_detect.fillna(0, inplace=True)
            df_detect.replace([np.inf, -np.inf], 0, inplace=True)
            l = len(df_detect)
            
            for i in range(0, l, 1000):
                df_detect_data = None
                if i + 1000 <= l:
                    df_detect_data = df_detect.iloc[i:i+1000,:]
                else:
                    df_detect_data = df_detect.iloc[i:,:]
                preds, err = detection(
                    
                    scaler=scaler,
                    som=som,
                    encoder=encoder,
                    
                    outliers_percentage=outliers_percentage,
                    winmap=winmap,
                    df=df_detect_data
                )
                
                if err:
                    print(err)
                    continue
                
                print(preds)
                df_detect_data['attack_type'] = preds
                df_SQL = df_detect_data[Setting.SELECTED_COLUMNS_SQL]
                
                df_SQL_DB = df_SQL.rename(columns={
                    "Src IP": "src_ip",
                    "Dst IP": "dst_ip",
                    
                    "Src Port": "src_port",
                    "Dst Port": "dst_port",
                    
                    "Protocol": "protocol",
                    "Timestamp": "timestamp",
                    "Flow Duration": "flow_duration",
                })
                sql_datas = df_SQL_DB.to_dict('records')
                try:
                    with engine.connect() as conn:
                        insert_ai_events(conn, sql_datas)
                except Exception as e:
                    print(e.__str__())

        except Exception as e:
            print(e.__str__())
            continue
        
