import logging

class EmojiFormatter(logging.Formatter):
    level_to_emoji = {
        logging.DEBUG: '🐛',
        logging.INFO: 'ℹ️',
        logging.WARNING: '⚠️',
        logging.ERROR: '❌',
        logging.CRITICAL: '🚨',
    }
    def format(self, record):
        record.levelname = f'{self.level_to_emoji[record.levelno]} {record.levelname}'
        return super().format(record)

logger = logging.getLogger('SubIO')
logger.addHandler(logging.StreamHandler())

# format log
formatter = EmojiFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger.handlers[0].setFormatter(formatter)