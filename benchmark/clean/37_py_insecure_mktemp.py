import tempfile
def temp_log():
    return tempfile.NamedTemporaryFile(delete=False, suffix='.log').name
