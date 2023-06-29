from sqlalchemy.sql.expression import text
import socket
import struct
from datetime import datetime

INSERT_AI_EVENTS = \
"""
INSERT INTO ai_events(src_ip, dst_ip, src_port, dst_port, protocol, timestamp, flow_duration, attack_type)
VALUES({0}, {1}, {2}, {3}, {4}, '{5}', {6}, {7});
"""

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def normalize_time(time):
    datetime_object = datetime.strptime(time, "%d/%m/%Y %H:%M:%S %p")
    return datetime_object

def normalize_time_2(time):
    return datetime.fromtimestamp(time / 1e3)

def insert_ai_event(conn, data):
    try:
        conn.execute(text(INSERT_AI_EVENTS.format(
            ip2int(data['src_ip']),
            ip2int(data['dst_ip']),
            
            data['src_port'],
            data['dst_port'],
            data['protocol'],
            
            normalize_time(data['timestamp']),
            data['flow_duration'],
            data['attack_type']
        )))
        
    except Exception as e:
        print(e.__str__())
        print("Can't Insert {0}".format(str(data)))
    
def insert_ai_events(conn, datas):
    for data in datas:
        if data['attack_type'] > 1:
            try:
                insert_ai_event(conn, data)
            except Exception as e:
                print(e.__str__())
                continue