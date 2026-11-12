from arango import ArangoClient
import os

def get_client():
    client = ArangoClient(hosts=os.getenv("ARANGO_URL", "http://localhost:8529"))
    return client.db('_system')
