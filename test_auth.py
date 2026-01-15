import pytest


@pytest.fixture
def getcode(get):

    responsegetCode =get("/auth/code")

    return responsegetCode
    


def test_login_success(secure_post, config,getcode):

    # # 4. 解析 JSON 并提取 uuid
    if getcode.status_code == 200:
        try:
            json_data = getcode.json()

            # 检查结构是否符合预期
            if json_data.get("code") == 200 and "data" in json_data:
                uuid = json_data["data"]["uuid"]
                print("UUID:", uuid)
            else:
                print("API 返回错误:", json_data.get("msg", "未知错误"))
        except ValueError:
            print("响应不是有效的 JSON")
    else:
        print(f"HTTP 请求失败: {getcode.status_code}")

    payload = {
        "clientId": config["clients"]["default_client_id"],
        "tenantId": config["clients"]["default_tenant_id"],
        "code": "0170",
        "uuid": uuid,
        "username": "admin",
        "password": "admin123",
        "grantType": "password"
    }
    
    response = secure_post("/auth/login", payload)
    
    assert response.status_code == 200
    # 进一步验证响应内容...