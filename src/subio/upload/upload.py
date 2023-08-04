import requests
from subio.log.log import logger

def upload(content, artifact):
    if 'upload' in artifact:
        logger.info(f"开始上传 {artifact['name']}")
        for upload_info in artifact['upload']:
            logger.info(f"上传 {artifact['name']} 到 {upload_info['to']}")
            upload_info['description'] = 'subio'
            upload_info['file_name'] = artifact['name']
            upload_info['content'] = content
            success = upload_to_gist(upload_info)
            if success:
                logger.info(f"上传 {artifact['name']} 到 {upload_info['to']} 成功")
            else:
                logger.error(f"上传 {artifact['name']} 到 {upload_info['to']} 失败")
    else:
        logger.info(f"artifact {artifact['name']} 没有配置上传")


def upload_to_gist(args):
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