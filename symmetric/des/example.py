"""
DES加解密模块使用示例
"""

try:
    from .des_cipher import DESCipher
except ImportError:
    from des_cipher import DESCipher


def text_encryption_example():
    """文本加解密示例"""
    print("=== DES文本加解密示例 ===")
    
    # 创建DES加密器（自动生成密钥）
    des = DESCipher()
    
    # 显示生成的密钥
    print(f"生成的密钥 (Base64): {des.get_key_base64()}")
    
    # 要加密的文本
    plaintext = "这是一个需要加密的秘密消息！Hello DES Encryption!"
    print(f"原文: {plaintext}")
    
    # CBC模式加密
    print("\n--- CBC模式加密 ---")
    encrypted_cbc = des.encrypt(plaintext, mode='CBC')
    print(f"加密结果: {encrypted_cbc}")
    
    # 解密
    decrypted_cbc = des.decrypt(encrypted_cbc)
    print(f"解密结果: {decrypted_cbc}")
    print(f"解密成功: {plaintext == decrypted_cbc}")
    
    # ECB模式加密
    print("\n--- ECB模式加密 ---")
    encrypted_ecb = des.encrypt(plaintext, mode='ECB')
    print(f"加密结果: {encrypted_ecb}")
    
    # 解密
    decrypted_ecb = des.decrypt(encrypted_ecb)
    print(f"解密结果: {decrypted_ecb}")
    print(f"解密成功: {plaintext == decrypted_ecb}")


def custom_key_example():
    """自定义密钥示例"""
    print("\n=== 自定义密钥示例 ===")
    
    # 使用自定义密钥
    custom_key = b'12345678'  # 8字节密钥
    des = DESCipher(custom_key)
    
    plaintext = "使用自定义密钥加密"
    print(f"原文: {plaintext}")
    print(f"密钥 (Base64): {des.get_key_base64()}")
    
    # 加密
    encrypted = des.encrypt(plaintext)
    print(f"加密结果: {encrypted}")
    
    # 解密
    decrypted = des.decrypt(encrypted)
    print(f"解密结果: {decrypted}")


def key_sharing_example():
    """密钥共享示例"""
    print("\n=== 密钥共享示例 ===")
    
    # 发送方
    sender = DESCipher()
    plaintext = "这是发送方要传输的机密信息"
    
    # 获取密钥用于共享
    shared_key = sender.get_key_base64()
    print(f"共享密钥: {shared_key}")
    
    # 加密消息
    encrypted_message = sender.encrypt(plaintext)
    print(f"加密消息: {encrypted_message}")
    
    # 接收方使用共享密钥创建解密器
    receiver = DESCipher.from_key_base64(shared_key)
    
    # 解密消息
    decrypted_message = receiver.decrypt(encrypted_message)
    print(f"解密消息: {decrypted_message}")
    print(f"传输成功: {plaintext == decrypted_message}")


def file_encryption_example():
    """文件加解密示例"""
    print("\n=== 文件加解密示例 ===")
    
    # 创建测试文件
    test_content = "这是一个测试文件的内容。\n包含多行文本。\n用于演示DES文件加解密功能。"
    
    with open('test_file.txt', 'w', encoding='utf-8') as f:
        f.write(test_content)
    print("创建测试文件: test_file.txt")
    
    # 创建DES加密器
    des = DESCipher()
    
    # 加密文件
    encryption_info = des.encrypt_file('test_file.txt', 'test_file_encrypted.bin', mode='CBC')
    print(f"文件加密完成: {encryption_info}")
    
    # 解密文件
    decrypted_file = des.decrypt_file('test_file_encrypted.bin', 'test_file_decrypted.txt', encryption_info)
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
        text_encryption_example()
        # custom_key_example()
        # key_sharing_example()
        # file_encryption_example()
        
        print("\n=== 所有示例运行完成 ===")
        
    except Exception as e:
        print(f"运行示例时出错: {e}")
        import traceback
        traceback.print_exc() 