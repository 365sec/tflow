from flask import Flask, Request
from flask import Blueprint
from scheduler import init_scheduler
from api import api
import logging




def create_app():
    log_filename = "flow_assets.log"
    logging.basicConfig(filename=log_filename, level=logging.DEBUG,
                        format='[%(asctime)s] %(levelname)s [%(funcName)s: %(filename)s, %(lineno)d] %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filemode='wb')
    logging.info("init-->")

    app = Flask(__name__)

    # api.init_app(app)
    app.register_blueprint(api)

    init_scheduler()
    app.run(debug=False,host='0.0.0.0',port=5050)
    print "create_app"


if __name__ == "__main__":
    create_app()
