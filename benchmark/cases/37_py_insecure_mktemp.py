import tempfile
def temp_log():
    return tempfile.mktemp(suffix='.log')
