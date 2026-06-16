import concurrent.futures
import time
import pandas as pd
import pathvalidate
import datetime

'''
X-Authtoken联系陈洋洋申请
'''
def random_end_txt():
    current_timestamp = int(time.time())
    return str(current_timestamp)
def input2html_history(search_input):
    import requests

    headers = {
        'X-Authtoken': 'e65cf226-ed6e-4761-b0e7-7a091621afb8',
    }

    params = {
        'query': search_input,
        'time_start': '2020-05-29 00:00:00',
    }


    try:
        response = requests.get('http://api.netlab.qihoo.net/urldb/v0/detail/', params=params, headers=headers)
        '''
        这个接口来自连鹏程的封装，api文档地址
        https://geelib.qihoo.net/geelib/knowledge/doc?spaceId=2312&docId=253370
        '''

        html = response.json()
        data = html["data"]

    except:
        return {"search_input": search_input}

    res = []
    for i in data:

        pre_res = {"search_input": search_input}

        pre_res.update(i)
        res.append(pre_res)

    data = res

    return data



if __name__ == '__main__':
    # 多线程执行

    # get_whois_info()

    res = []
    # 要请求的URL列表
    with open(r'input.txt', 'r', encoding='utf-8') as f:
        domains = list(f.read().splitlines())

    # 设置线程池大小，此处为5个线程
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=10)

    # 提交任务到线程池
    # results = pool.map(get_whois_info2registrarname, domains)
    results = pool.map(input2html_history, domains)

    # 获取结果
    for result in results:
        print(result)
        for i in range(0, len(result)):
            result[i]['check_time'] = datetime.datetime.fromtimestamp(int(result[i]['check_time'])).strftime("%Y-%m-%d")
        res += result



    df = pd.DataFrame(res)
    df.fillna('其他', inplace=True)

    end_text = random_end_txt()
    print(end_text)
    df.to_excel(f"get_whois_info2all_output{end_text}.xlsx", index=False)

#再把快照直接寫進文件
for item in res:
    check_time = str(item["check_time"])
    title = item["title"]
    html_content = item["html"]
    domain = item["search_input"]  # 获取对应的域名

    title = (pathvalidate.sanitize_filename(title))[0:50]
    # 将域名添加到文件名中
    file_name = end_text + "_" + domain + "_" + check_time + "_" + str(title) + ".html"
    with open(f"html/{file_name}", 'w', encoding='utf-8') as file:
        file.write(html_content)
