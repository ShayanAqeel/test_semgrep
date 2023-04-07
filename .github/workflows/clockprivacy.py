from routes import routes
from flask_cors import cross_origin
from flask import request
from routes.dec_fun.cytex_wrappers import validate_login, validate_time
from routes.dec_fun.errors_message import server_error
import traceback

from .process_clockprivacy import (
    process_get_server_list,
    process_get_server_tunnel_config,
    process_disconnect_server,
)

@routes.route("/get/server/list", methods=["POST"])
@cross_origin(origin="*", headers=["Content- Type", "application/json"])
def get_server_list():
    """
    GET SERVER LIST
    """
    try:
        return process_get_server_list(request.json)
    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))
    
@routes.route("/getservertunnelconfig/Connect", methods=["POST"])
@cross_origin(origin="*", headers=["Content- Type", "application/json"])
def get_server_tunnel_config():
    """
    GET SERVER LIST
    """
    try:
        return process_get_server_tunnel_config(request.json)
    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))
    
@routes.route("/disconnect/server", methods=["POST"])
@cross_origin(origin="*", headers=["Content- Type", "application/json"])
def disconnect_server():
    """
    GET SERVER LIST
    """
    try:
        return process_disconnect_server(request.json)
    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))
 


