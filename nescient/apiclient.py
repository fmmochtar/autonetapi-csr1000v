import requests


def report(source_ip, dst_ip, dst_port, conn_protocol, detection_time, report_url="http://localhost:8000/api/attacklog"):
    return requests.post(url=report_url, json={
        'source_ip': source_ip,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'conn_protocol': conn_protocol,
        'detection_time': detection_time
    })
