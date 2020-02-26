import logging
logger = logging.getLogger('tapp_flow')
log_filename = "flow_assets.log"
logging.basicConfig(filename=log_filename, level=logging.DEBUG,
                    format='[%(asctime)s] %(levelname)s [%(funcName)s: %(filename)s, %(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filemode='wb')
# logger.debug("efawefawf")