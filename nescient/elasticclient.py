import os

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv(verbose=True)

client_from_env = Elasticsearch(hosts=[os.getenv('ELASTIC_HOST')])
index_form_env = os.getenv('ELASTIC_INDEX')


def get_netflow_agg(start_time="now", end_time="now-3s", client=client_from_env, index=index_form_env) -> list:
    response = client.search(
        index=index,
        body={
            "size": "0",
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": end_time,
                        "lte": start_time
                    }
                }
            },
            "aggs": {
                "packets": {
                    "sum": {
                        "field": "netflow.packet_delta_count"
                    }
                },
                "USIP": {
                    "cardinality": {
                        "field": "netflow.source_ipv4_address"
                    }
                },
                "UDIP": {
                    "cardinality": {
                        "field": "netflow.destination_ipv4_address"
                    }
                },
                "UPR": {
                    "cardinality": {
                        "field": "netflow.protocol_identifier"
                    }
                }
            }
        }
    )
    return response['aggregations']


def get_netflow_resampled(start_time: str, end_time: str, client=client_from_env, index=index_form_env) -> list:
    response = client.search(
        index=index,
        body={
            "size": 0,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": start_time,
                        "lte": end_time
                    }
                }
            },
            "aggs": {
                "all_attributes": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "3s"
                    },
                    "aggs": {
                        "packets": {
                            "sum": {
                                "field": "netflow.packet_delta_count"
                            }
                        },
                        "USIP": {
                            "cardinality": {
                                "field": "netflow.source_ipv4_address"
                            }
                        },
                        "UDIP": {
                            "cardinality": {
                                "field": "netflow.destination_ipv4_address"
                            }
                        },
                        "UPR": {
                            "cardinality": {
                                "field": "netflow.protocol_identifier"
                            }
                        }
                    }
                }
            }
        }
    )
    return response["aggregations"]["all_attributes"]["buckets"]


def get_netflow_data_at_time(time: str, client=client_from_env, index=index_form_env) -> dict:
    response = client.search(
        index=index,
        body={
            "size": 1,
            "query": {
                "match": {
                    "@timestamp": time
                }
            },
            "_source": [
                "netflow.source_ipv4_address",
                "netflow.destination_ipv4_address",
                "netflow.destination_transport_port",
                "netflow.protocol_identifier"
            ]
        }
    )
    return response['hits']['hits'][0]['netflow']
