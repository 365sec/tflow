
from flask import Blueprint, current_app
from flask_restplus import Api
from flow.task import task_namespace


api = Blueprint("api", __name__, url_prefix="/api/vcan")

SCANAPP_API_v1 = Api(api,  doc='/apidoc/', version="vcan")
SCANAPP_API_v1.add_namespace(task_namespace)

