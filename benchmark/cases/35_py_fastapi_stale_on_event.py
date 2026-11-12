from fastapi import FastAPI
app = FastAPI()
@app.on_event('startup')
def setup_db():
    init_pool()
