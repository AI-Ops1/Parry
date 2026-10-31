import pydantic

def serialize_payload(model_cls, raw_data: dict) -> dict:
    instance = pydantic.parse_obj_as(model_cls, raw_data)
    return instance.dict()
