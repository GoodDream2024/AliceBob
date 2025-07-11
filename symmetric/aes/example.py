"""
AES加解密模块使用示例
"""

try:
    from .aes_cipher import AESCipher
except ImportError:
    from aes_cipher import AESCipher


def text_encryption_example():
    """文本加解密示例"""
    print("=== AES文本加解密示例 ===")
    
    # 创建AES加密器（默认AES-256）
    aes = AESCipher()
    
    # 显示密钥信息
    key_info = aes.get_key_info()
    print(f"算法: {key_info['algorithm']}")
    print(f"密钥长度: {key_info['key_size_bits']}位")
    print(f"密钥 (Base64): {key_info['key_base64']}")
    
    # 要加密的文本
    plaintext = "这是一个需要加密的秘密消息！Hello AES Encryption!"
    print(f"原文: {plaintext}")
    
    # CBC模式加密
    print("\n--- CBC模式加密 ---")
    encrypted_cbc = aes.encrypt(plaintext, mode='CBC')
    print(f"加密结果: {encrypted_cbc}")
    
    # 解密
    decrypted_cbc = aes.decrypt(encrypted_cbc)
    print(f"解密结果: {decrypted_cbc}")
    print(f"解密成功: {plaintext == decrypted_cbc}")
    
    # GCM模式加密（认证加密）
    print("\n--- GCM模式加密（推荐） ---")
    encrypted_gcm = aes.encrypt(plaintext, mode='GCM')
    print(f"加密结果: {encrypted_gcm}")
    
    # 解密
    decrypted_gcm = aes.decrypt(encrypted_gcm)
    print(f"解密结果: {decrypted_gcm}")
    print(f"解密成功: {plaintext == decrypted_gcm}")
    
    # ECB模式加密
    print("\n--- ECB模式加密 ---")
    encrypted_ecb = aes.encrypt(plaintext, mode='ECB')
    print(f"加密结果: {encrypted_ecb}")
    
    # 解密
    decrypted_ecb = aes.decrypt(encrypted_ecb)
    print(f"解密结果: {decrypted_ecb}")
    print(f"解密成功: {plaintext == decrypted_ecb}")


def different_key_sizes_example():
    """不同密钥长度示例"""
    print("\n=== 不同AES密钥长度示例 ===")
    
    plaintext = "测试不同密钥长度的AES加密"
    
    # AES-128
    print("\n--- AES-128 ---")
    aes128 = AESCipher(key_size=16)
    key_info = aes128.get_key_info()
    print(f"算法: {key_info['algorithm']}")
    
    encrypted = aes128.encrypt(plaintext)
    decrypted = aes128.decrypt(encrypted)
    print(f"加密解密成功: {plaintext == decrypted}")
    
    # AES-192
    print("\n--- AES-192 ---")
    aes192 = AESCipher(key_size=24)
    key_info = aes192.get_key_info()
    print(f"算法: {key_info['algorithm']}")
    
    encrypted = aes192.encrypt(plaintext)
    decrypted = aes192.decrypt(encrypted)
    print(f"加密解密成功: {plaintext == decrypted}")
    
    # AES-256
    print("\n--- AES-256 ---")
    aes256 = AESCipher(key_size=32)
    key_info = aes256.get_key_info()
    print(f"算法: {key_info['algorithm']}")
    
    encrypted = aes256.encrypt(plaintext)
    decrypted = aes256.decrypt(encrypted)
    print(f"加密解密成功: {plaintext == decrypted}")


def custom_key_example():
    """自定义密钥示例"""
    print("\n=== 自定义密钥示例 ===")
    
    # 使用自定义密钥（32字节 = AES-256）
    custom_key = b'abcdefghijklmnopqrstuvwxyz123456'  # 32字节密钥
    aes = AESCipher(custom_key)
    
    plaintext = "使用自定义密钥加密"
    print(f"原文: {plaintext}")
    
    key_info = aes.get_key_info()
    print(f"算法: {key_info['algorithm']}")
    print(f"密钥 (Base64): {key_info['key_base64']}")
    
    # 加密
    encrypted = aes.encrypt(plaintext, mode='GCM')
    print(f"加密结果: {encrypted}")
    
    # 解密
    decrypted = aes.decrypt(encrypted)
    print(f"解密结果: {decrypted}")
    print(f"解密成功: {plaintext == decrypted}")


def key_sharing_example():
    """密钥共享示例"""
    print("\n=== 密钥共享示例 ===")
    
    # 发送方
    sender = AESCipher()
    plaintext = "这是发送方要传输的机密信息"
    
    # 获取密钥用于共享
    shared_key = sender.get_key_base64()
    print(f"共享密钥: {shared_key}")
    
    # 加密消息
    encrypted_message = sender.encrypt(plaintext, mode='GCM')
    print(f"加密消息: {encrypted_message}")
    
    # 接收方使用共享密钥创建解密器
    receiver = AESCipher.from_key_base64(shared_key)
    
    # 解密消息
    decrypted_message = receiver.decrypt(encrypted_message)
    print(f"解密消息: {decrypted_message}")
    print(f"传输成功: {plaintext == decrypted_message}")


def file_encryption_example():
    """文件加解密示例"""
    print("\n=== 文件加解密示例 ===")
    
    # 创建测试文件
    test_content = "这是一个测试文件的内容。\n包含多行文本。\n用于演示AES文件加解密功能。\n支持各种文件类型的加密。"
    
    with open('test_file.txt', 'w', encoding='utf-8') as f:
        f.write(test_content)
    print("创建测试文件: test_file.txt")
    
    # 创建AES加密器
    aes = AESCipher()
    key_info = aes.get_key_info()
    print(f"使用 {key_info['algorithm']} 加密文件")
    
    # 加密文件
    encryption_info = aes.encrypt_file('test_file.txt', 'test_file_encrypted.bin', mode='GCM')
    print(f"文件加密完成: {encryption_info}")
    
    # 解密文件
    decrypted_file = aes.decrypt_file('test_file_encrypted.bin', 'test_file_decrypted.txt', encryption_info)
    print(f"文件解密完成: {decrypted_file}")
    
    # 验证文件内容
    with open('test_file_decrypted.txt', 'r', encoding='utf-8') as f:
        decrypted_content = f.read()
    
    print(f"原文件内容: {repr(test_content)}")
    print(f"解密文件内容: {repr(decrypted_content)}")
    print(f"文件解密成功: {test_content == decrypted_content}")
    
    # 清理临时文件
    import os
    os.remove('test_file.txt')
    os.remove('test_file_encrypted.bin')
    os.remove('test_file_decrypted.txt')
    print("清理临时文件完成")


if __name__ == "__main__":
    try:
        # 运行所有示例
        # text_encryption_example()
        # different_key_sizes_example()
        # custom_key_example()
        key_sharing_example()
        # file_encryption_example()
        
        print("\n=== 所有示例运行完成 ===")
        
    except Exception as e:
        print(f"运行示例时出错: {e}")
        import traceback
        traceback.print_exc() 