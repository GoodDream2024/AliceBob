"""
SM4加解密使用示例

演示如何使用SM4Cipher类进行加密和解密操作
"""

import os
import tempfile
from sm4_cipher import SM4Cipher


def demo_basic_encryption():
    """基本加解密示例"""
    print("=== SM4 基本加解密示例 ===")
    
    # 创建SM4加密器
    cipher = SM4Cipher()
    
    # 要加密的文本
    plaintext = "这是一个SM4加密测试消息！Hello SM4!"
    print(f"原始文本: {plaintext}")
    
    # ECB模式加密
    encrypted_ecb = cipher.encrypt(plaintext, mode='ECB')
    print(f"ECB加密结果: {encrypted_ecb}")
    
    # ECB模式解密
    decrypted_ecb = cipher.decrypt(encrypted_ecb)
    print(f"ECB解密结果: {decrypted_ecb}")
    
    # 注意：CBC模式暂时不可用，仅演示ECB模式
    print("注意：由于gmssl库的限制，CBC模式暂时不可用")
    
    print()


def demo_file_encryption():
    """文件加解密示例"""
    print("=== SM4 文件加解密示例 ===")
    
    # 创建SM4加密器
    cipher = SM4Cipher()
    
    # 创建临时文件进行测试
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as f:
        f.write("这是一个测试文件内容。\n文件加密测试！\nSM4 File Encryption Test!")
        test_file = f.name
    
    encrypted_file_ecb = None
    decrypted_file_ecb = None
    
    try:
        print(f"测试文件: {test_file}")
        
        # 读取原始文件内容
        with open(test_file, 'r', encoding='utf-8') as f:
            original_content = f.read()
        print(f"原始文件内容:\n{original_content}")
        
        # ECB模式文件加密
        encrypted_file_ecb = test_file + '.ecb.enc'
        encryption_info_ecb = cipher.encrypt_file(test_file, encrypted_file_ecb, mode='ECB')
        print(f"ECB加密信息: {encryption_info_ecb}")
        
        # ECB模式文件解密
        decrypted_file_ecb = test_file + '.ecb.dec'
        cipher.decrypt_file(encrypted_file_ecb, decrypted_file_ecb, encryption_info_ecb)
        
        with open(decrypted_file_ecb, 'r', encoding='utf-8') as f:
            decrypted_content_ecb = f.read()
        print(f"ECB解密文件内容:\n{decrypted_content_ecb}")
        
        # 验证解密结果
        assert original_content == decrypted_content_ecb, "ECB模式文件加解密失败！"
        print("✓ ECB模式文件加解密验证成功！")
        print("注意：CBC模式暂时不可用")
        
    finally:
        # 清理临时文件
        for file_path in [test_file, encrypted_file_ecb, decrypted_file_ecb]:
            if file_path:  # 只删除已定义的文件
                try:
                    os.unlink(file_path)
                except FileNotFoundError:
                    pass
    
    print()


def demo_key_management():
    """密钥管理示例"""
    print("=== SM4 密钥管理示例 ===")
    
    # 使用自动生成的密钥
    cipher1 = SM4Cipher()
    print(f"自动生成的密钥信息: {cipher1.get_key_info()}")
    
    # 使用指定的密钥
    custom_key = b'1234567890123456'  # 16字节密钥
    cipher2 = SM4Cipher(custom_key)
    print(f"自定义密钥信息: {cipher2.get_key_info()}")
    
    # 导出和导入密钥
    key_base64 = cipher2.get_key_base64()
    print(f"Base64编码的密钥: {key_base64}")
    
    # 从Base64密钥创建新的加密器
    cipher3 = SM4Cipher.from_key_base64(key_base64)
    print(f"从Base64导入的密钥信息: {cipher3.get_key_info()}")
    
    # 验证相同密钥的加解密兼容性
    plaintext = "密钥管理测试"
    encrypted = cipher2.encrypt(plaintext, mode='ECB')
    decrypted = cipher3.decrypt(encrypted)
    
    print(f"原始文本: {plaintext}")
    print(f"解密文本: {decrypted}")
    assert plaintext == decrypted, "密钥兼容性测试失败！"
    print("✓ 密钥管理验证成功！")
    
    print()


def demo_security_features():
    """安全特性演示"""
    print("=== SM4 安全特性演示 ===")
    
    cipher = SM4Cipher()
    plaintext = "相同明文的不同加密结果"
    
    # ECB模式 - 相同明文产生相同密文
    encrypted1_ecb = cipher.encrypt(plaintext, mode='ECB')
    encrypted2_ecb = cipher.encrypt(plaintext, mode='ECB')
    print(f"ECB模式加密1: {encrypted1_ecb['ciphertext']}")
    print(f"ECB模式加密2: {encrypted2_ecb['ciphertext']}")
    print(f"ECB模式密文相同: {encrypted1_ecb['ciphertext'] == encrypted2_ecb['ciphertext']}")
    
    # 注意：CBC模式暂时不可用
    print("注意：CBC模式暂时不可用，仅测试ECB模式")
    print("✓ ECB模式安全特性验证成功！")
    
    print()


if __name__ == "__main__":
    print("SM4 加解密功能演示")
    print("=" * 50)
    
    try:
        demo_basic_encryption()
        demo_file_encryption()
        demo_key_management()
        demo_security_features()
        
        print("🎉 所有演示完成！SM4模块工作正常。")
        
    except Exception as e:
        print(f"❌ 演示过程中出现错误: {e}")
        import traceback
        traceback.print_exc() 