from langchain_text_splitters import RecursiveCharacterTextSplitter
def chunk(doc):
    return RecursiveCharacterTextSplitter().split_text(doc)
