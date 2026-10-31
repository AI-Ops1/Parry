import arangodb_driver

def connect_graph(url: str):
    return arangodb_driver.Client(url)
