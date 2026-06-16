import requests
import random
import hashlib
import time
import concurrent.futures
import pandas as pd


'''
需要申请appid，secret

http://share.cloud.safe.360.net/ApiService/detail/0f1dbe38-477f-46b1-8a25-4ea6a1ed78eb
'''
def random_end_txt():
    current_timestamp = int(time.time())
    return str(current_timestamp)
'''
http://apidoc.qihoo.net:8360/apidoc/innerapis/urls/std/outchain_v1/

{
    "code": "0",
    "msg": "success",
    "data": {
        "results": [
            {
                "info": {
                    "exts": [],
                    "level": 0,
                    "sub_level": 0
                },
                "url": "ljhuawgx.com"
            }
        ],
        "exts": []
    }
}

'''

def make_headers(appid, secret, body) :
    headers = {}
    headers["X-360-Key"] = appid
    headers["X-360-Nonce"] = str(random.randint(0,99999999)).zfill(8)
    headers["X-360-Timestamp"] = str(int(time.time()))

    s = hashlib.md5(body.encode("utf8")).hexdigest() + headers["X-360-Key"] + headers["X-360-Nonce"] + headers["X-360-Timestamp"] + secret
    md5 = hashlib.md5(s.encode("utf8")).hexdigest()
    headers["X-360-Signature"] = md5[16:]
    headers["Content-Type"] = "application/json"
    return headers





def wd_v1_now(url_i = 'ljhuawgx.com'):

    appid = '8caf5d038722624364c0' # 自行申请
    secret = '2efeec4e0c3d9649629663174c91d7f8f565a6c8' # 自行申请
    url = 'http://api.safe.qihoo.net/urls/std/v1/cloud_safe_info'
    # url = 'http://ljhuawg.com'
    # body = '{"data": [{"url":"http://map.so.com/?src=tab_web"}]}'
    body = '{"data": [{"url":"' + url_i + '"}]}'
    res =  requests.post(url, data=body, headers=make_headers(appid, secret, body))


    html = res.json()
    url = html['data']['results'][0]['url']
    level = html['data']['results'][0]['info']['level']

    if 0<= level < 50:
        level_res = "未知"
    elif level == 50:
        level_res = "灰"
    elif level == 60:
        level_res = "黑"
    elif level == 70:
        level_res = "黑"
    else:
        level_res = "其他"
    level_res = "恶意" if level == 60 else "未知"

    sub_level = html['data']['results'][0]['info']['sub_level']

    data = {"url": url_i, "level": level, "sub_level": sub_level,"level_res": level_res}
    print(data)

    return data


if __name__ == '__main__':
    # wd_v1_now()
    # 要请求的URL列表

    res = []
    import os
    file_path = os.path.join(os.path.dirname(__file__), 'input.txt')
    with open(file_path, 'r', encoding='utf-8') as f:
        srcip = list(f.read().splitlines())

    # 设置线程池大小，此处为5个线程
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=5)

    # 提交任务到线程池
    results = pool.map(wd_v1_now, srcip)

    # 获取结果
    for result in results:
        print(result)
        res.append(result)


    df1 = pd.DataFrame(res)

    end_txt = random_end_txt()
    df1.to_excel(f'output_{end_txt}.xlsx', index=False)
    print(f'output_{end_txt}.xlsx')