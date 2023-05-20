import requests
from subio.app.log import logger

def upload(args):
    to = args['to']
    if to == 'gist':
        resp = requests.patch(
            f"https://api.github.com/gists/{args['id']}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {args['token']}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={
                "description": args['description'],
                "files": {
                    args['file_name']: {
                        "content": args['content'],
                    }
                }
            }
        )
        if resp.status_code == 200:
            return True
        logger.info(resp.text)
        return False
    else:
        print(f"Unknown upload destination: {to}")
        return False