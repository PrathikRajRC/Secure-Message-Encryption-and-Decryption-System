import logging

def setup_logger():
    logging.basicConfig(filename='crypto_app.log', level=logging.INFO)

def log_activity(activity):
    logging.info(activity)
