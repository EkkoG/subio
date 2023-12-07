import requests
from subio.log.log import logger

def check(config):
    for index, up in enumerate(config):
        if 'to' not in up:
            logger.error(f"upload {index} 没有配置 to")
            return False
    return True


def upload(content, artifact, uploaders):
    if 'upload' in artifact and len(artifact['upload']) > 0 and check(artifact['upload']):
        for upload_info in artifact['upload']:
            uploader = list(filter(lambda uploader: uploader['name'] == upload_info['to'], uploaders))
            if len(uploader) == 0:
                logger.error(f"artifact {artifact['name']} 没有找到上传器 {upload_info['to']}")
                continue
            if uploader[0]['type'] == 'gist':
                
                logger.info(f"开始上传 {artifact['name']}")
                logger.info(f"上传 {artifact['name']} 到 {upload_info['to']}")
                upload_info['description'] = 'subio'
                upload_info['file_name'] = artifact['name']
                upload_info['content'] = content
                upload_info['id'] = uploader[0]['id']
                upload_info['token'] = uploader[0]['token']
                success = upload_to_gist(upload_info)
                if success:
                    logger.info(f"上传 {artifact['name']} 到 {upload_info['to']} 成功")
                else:
                    logger.error(f"上传 {artifact['name']} 到 {upload_info['to']} 失败")
            else:
                logger.error(f"artifact {artifact['name']} 不支持上传到 {upload_info['to']}")
    else:
        logger.info(f"artifact {artifact['name']} 没有配置上传或者配置错误")


def upload_to_gist(args):
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