import string
import random
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# ---------------------- 加密函数（复用之前的，用于测试） ----------------------
def generate_32bit_aes_key() -> str:
    """生成32位AES密钥（复刻后端RandomUtil.randomString(32)）"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))

def aes_encrypt_hutool(plain_text: str, aes_32bit_key: bytes) -> str:
    """AES加密（Hutool规则）"""
    key_bytes = aes_32bit_key.encode("utf-8")
    plain_bytes = plain_text.encode("utf-8")
    iv_bytes = key_bytes[:16]
    
    # PKCS7填充
    padder = padding.PKCS7(128).padder()
    padded_plain_bytes = padder.update(plain_bytes) + padder.finalize()
    
    # 加密
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes))
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(padded_plain_bytes) + encryptor.finalize()
    
    # Base64编码
    return base64.b64encode(encrypted_bytes).decode("utf-8")

# ---------------------- 解密函数（核心） ----------------------
def aes_decrypt_hutool(encrypted_base64: str, aes_32bit_key: str) -> str:
    """
    AES解密（完全对齐Hutool SecureUtil.aes().decryptBase64()）
    :param encrypted_base64: 加密后的Base64字符串
    :param aes_32bit_key: 加密时用的32位AES密钥
    :return: 解密后的原始明文
    """
    # 步骤2：Base64解码
    encrypted_bytes = base64.b64decode(encrypted_base64)
    
    # 步骤3：密钥转字节+生成IV
    key_bytes = aes_32bit_key.encode("utf-8")
    iv_bytes = key_bytes[:16]
    
    # 步骤4：初始化解密器
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes))
    decryptor = cipher.decryptor()
    
    # 步骤5：执行解密
    decrypted_padded_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()
    
    # 步骤6：PKCS7去填充
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_plain_bytes = unpadder.update(decrypted_padded_bytes) + unpadder.finalize()
    
    # 步骤7：转UTF-8字符串
    return decrypted_plain_bytes.decode("utf-8")

# ---------------------- 测试验证（加密→解密，闭环验证） ----------------------
if __name__ == "__main__":
    # 1. 生成32位密钥
    aes_key = generate_32bit_aes_key()
    print(f"32位AES密钥：{aes_key}")
    
    # 2. 原始明文
    original_text = "这是要加密的原始内容"
    print(f"原始明文：{original_text}")
    
    # 3. 加密
    encrypted_str = aes_encrypt_hutool(original_text, aes_key)
    print(f"加密后Base64字符串：{encrypted_str}")
    
    # 4. 解密
    decrypted_text = aes_decrypt_hutool(encrypted_str, aes_key)
    print(f"解密后明文：{decrypted_text}")
    
    # 验证：解密结果和原始明文一致
    assert decrypted_text == original_text, "解密结果和原始明文不一致！"
    print("✅ 加密→解密闭环验证成功！")