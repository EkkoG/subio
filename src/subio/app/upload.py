import requests
def upload(args):
    to = args['to']
    if to == 'gist':
        pass
#     curl -L \
#   -X PATCH \
#   -H "Accept: application/vnd.github+json" \
#   -H "Authorization: Bearer <YOUR-TOKEN>"\
#   -H "X-GitHub-Api-Version: 2022-11-28" \
#   https://api.github.com/gists/GIST_ID \
#   -d '{"description":"An updated gist description","files":{"README.md":{"content":"Hello World from GitHub"}}}'
        requests.patch(
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
    else:
        print(f"Unknown upload destination: {to}")