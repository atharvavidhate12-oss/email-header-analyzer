from email import policy
from email.parser import BytesParser

def parse_eml(file_path):
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = dict(msg.items())
    body = msg.get_body(preferencelist=('plain'))

    return headers, body.get_content() if body else ""
