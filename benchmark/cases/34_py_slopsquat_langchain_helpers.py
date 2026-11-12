from langchain_community_helpers import SmartTextSplitter
def chunk(doc):
    return SmartTextSplitter().split(doc)
