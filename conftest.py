import pytest
from utils.config_loader import load_config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from utils.aes import * 
from utils.crypto import _encrypt_body


# # baseurl
# @pytest.fixture()
# def baseurl():
#     return f"{config['server']['scheme']}://{config['server']['host']}:{config['server']['port']}" 


#  注册 --env 参数
def pytest_addoption(parser):
    parser.addoption(
        "--env",
        action="store",
        default="dev",
        help="运行环境: dev, test, prod"
    )


# aes密钥
@pytest.fixture()
def aes_key():
    return generate_32bit_aes_key() 

# 全局配置 fixture
@pytest.fixture(scope="session")
def config(request):
    env = request.config.getoption("--env")  # ← 从命令行获取
    return load_config(env)  # 可通过 pytest --env=prod 切换

# 自动生成加密请求头
@pytest.fixture()
def encrypt_header(config,aes_key):

    # 1. 生成32位AES原始密钥（bytes类型）
    
    print(aes_key)
    if not aes_key or len(aes_key) != 32:
        raise ValueError("生成的AES密钥不是32位bytes，不符合AES-256要求")
    
    # 2. 对原始AES密钥做Base64编码 → 得到字符串（关键！和服务端对齐）
    # print(type(base64.b64encode(aes_key_bytes)))
    aes_key_b64 = base64.b64encode(aes_key.encode("utf-8"))

    # 3. 将公钥 对象化
    rsa_public_key = serialization.load_pem_public_key(
            config["encrypt"]["rsa_public_key_pem"].encode("utf-8"),
            backend=default_backend()
        )
    # 4. 使用公钥加密
    encrypted_aes = _encrypt_body(
        rsa_public_key,
        aes_key_b64
    )
    return {
        config["encrypt"]["header_flag"]: encrypted_aes,
        "Content-Type": "text/plain; charset=UTF-8"
    }

# 自动加密的 POST 请求工具
@pytest.fixture()
def secure_post(config, encrypt_header,aes_key):
    from utils.http_client_custom import CryptoSession
    
    baseurl = f"{config['server']['scheme']}://{config['server']['host']}:{config['server']['port']}"

    # aes
    def _aespost(endpoint: str, payload: dict):
        # 创建加密Session
        session = CryptoSession(aes_key=aes_key)
        url = baseurl + endpoint
        return session.post(url,headers=encrypt_header, json=payload)    

    # 参考
    # def _post(endpoint: str, payload: dict):
    #     # 1. 生成 AES 密钥（实际应与 encrypt_header 中一致）
    #     aes_key = "your_dynamic_aes_key_32bytes!!"

    #     # 2. 加密 body
    #     encrypted_body = aes_cbc_encrypt(json.dumps(payload), aes_key)

    #     # 3. 构造 URL
    #     url = f"{config['server']['scheme']}://{config['server']['host']}:{config['server']['port']}{endpoint}"

    #     # 4. 发送请求
    #     resp = requests.post(url, data=encrypted_body, headers=encrypt_header)
    #     return resp


    return _aespost

@pytest.fixture()
def get(config):
    import requests
    baseurl = f"{config['server']['scheme']}://{config['server']['host']}:{config['server']['port']}"

    def _get(endpoint: str):
        url = baseurl+endpoint
        return requests.get(url)
    return _get
    