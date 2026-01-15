import requests
import json as json11
from typing import Any, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import utils.aes as aes
import base64
from urllib.parse import urlunparse

class CryptoSession(requests.Session):
    """支持自动加密POST/PUT请求体的Session"""
    def __init__(self, aes_key: str):
        super().__init__()
        self.aes_key_bytes=aes_key


    def request(self, method: str, url: str, 
                params: Optional[Dict[str, Any]] = None,
                data: Optional[Any] = None,
                json: Optional[Dict[str, Any]] = None,
                **kwargs) -> requests.Response:
        """重写request方法，自动加密POST/PUT的body"""
        # 仅处理POST/PUT请求
        if method.upper() in ["POST", "PUT"]:

                try:
                    # 1. 检查请求头是否包含加密标记（headerFlag）

                    
                    # 2. 生成32位AES原始密钥（bytes类型）
                    # 必须返回32位bytes（AES-256要求）
                    print(self.aes_key_bytes)
                    if not self.aes_key_bytes or len(self.aes_key_bytes) != 32:
                        raise ValueError("生成的AES密钥不是32位bytes，不符合AES-256要求")
                    
                    # 3. 对原始AES密钥做Base64编码 → 得到字符串（关键！和服务端对齐）
                    # print(type(base64.b64encode(self.aes_key_bytes)))

                    
                    # 4. RSA加密「Base64编码后的AES密钥字符串」→ 放到请求头
                        # _encrypt_body是RSA加密方法
                    
                    
                    # 5. 用「Base64编码后的AES密钥字符串」加密请求体（核心修正！和服务端对齐）
                    print(type(json11.dumps(json)))
                    encrypted_data = aes.aes_encrypt_hutool(json11.dumps(json), self.aes_key_bytes)
                    
                    
                    # 6. 更新kwargs：替换data为加密后的内容，更新headers
                    data = encrypted_data

                    print("-----------------------------------------------------------------------------")
                    print(data)
                except KeyError as e:
                    # 针对性捕获：请求头缺少加密标记
                    raise RuntimeError(f"加密准备失败：{str(e)}") from e
                except ValueError as e:
                    # 针对性捕获：密钥生成异常
                    raise RuntimeError(f"AES密钥生成失败：{str(e)}") from e
                except Exception as e:
                    # 其他异常：兜底但不隐藏，抛出明确错误
                    raise RuntimeError(f"请求体加密失败：{str(e)}") from e


        # 调用父类的request方法发送请求
        return super().request(
            method=method,
            url=url,
            params=params,
            data=data,
            json=json,
            **kwargs
        )
    

# 使用示例
if __name__ == "__main__":
    # 配置（和服务端对齐）
    ENCRYPT_HEADER_FLAG = "encrypt-key"
    RSA_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALSlBocI1tNlduobXXRKSbW8mqHuYO0a
YkFD6ARcmj9NehtCRHTXV+I1vNLRU9kJoWLN67EQph8oyySzUnncMGMCAwEAAQ==
-----END PUBLIC KEY-----"""


# -------------------------------------------------------组装url + uuid获取------------------------------------------------------------#

    # 1. 拆分定义各部分
    scheme = "http"  # 协议（对应上面的 protocol）
    host = "localhost"
    port = 8080
    getCodepath = "/auth/code"  # 对应 uri
    query_params = "id=100"  # 查询参数（也可以用 params 传，这里演示完整构造）

    # 2. 构造 URL 各部分的元组（必须按这个顺序：scheme, netloc, path, params, query, fragment）
    # netloc = host:port（端口转字符串）
    netloc = f"{host}:{str(port)}"
    url_parts = (scheme, netloc, getCodepath, "", "", "")
    # 3. 生成完整 URL
    full_url = urlunparse(url_parts)
# -------------------------------------------------------组装url + uuid获取-------------------------------------------------------#
    
    responsegetCode=requests.get(full_url)
    
# -------------------------------------------------------uuid获取-------------------------------------------------------#

    # # 4. 解析 JSON 并提取 uuid
    if responsegetCode.status_code == 200:
        try:
            json_data = responsegetCode.json()

            # 检查结构是否符合预期
            if json_data.get("code") == 200 and "data" in json_data:
                uuid = json_data["data"]["uuid"]
                print("UUID:", uuid)
            else:
                print("API 返回错误:", json_data.get("msg", "未知错误"))
        except ValueError:
            print("响应不是有效的 JSON")
    else:
        print(f"HTTP 请求失败: {responsegetCode.status_code}")
# -------------------------------------------------------uuid获取-------------------------------------------------------#



    # 创建加密Session
    session = CryptoSession(
        encrypt_header_flag=ENCRYPT_HEADER_FLAG,
        rsa_public_key_pem=RSA_PUBLIC_KEY_PEM
    )

    # 获取uuid
       
    # 1. POST请求（自动加密json）
    url = "http://localhost:8080/auth/login"
    # url="http://www.baidu.com/"
    payload = {
        "clientId": "e5cd7e4891bf95d1d19206ce24a7b32e",
        "tenantId": "000000",
        "code": "0170",
        "uuid": "uuid",
        "username": "admin",
        "password": "admin123",
        "grantType":"password"
    }

    
    header={
        "encrypt-key":"",
        "Content-Type": "text/plain; charset=UTF-8"
    }
    response = session.post(url,headers=header, json=payload)
    print("POST响应：", response.text)


    # 2. PUT请求（自动加密json）
    # put_url = "http://localhost:8080/api/test/1"
    # put_payload = {"name": "修改后", "age": 20}
    # put_response = session.put(put_url, json=put_payload)
    # print("PUT响应：", put_response.text)

    # 3. GET请求（不加密，正常放行）
    # get_response = session.get("http://localhost:8080/api/test")
    # print("GET响应：", get_response.text)



