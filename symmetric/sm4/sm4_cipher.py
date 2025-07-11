"""
SM4加解密实现

使用gmssl库实现国密SM4算法的加密和解密功能
目前支持ECB模式（CBC模式由于gmssl库的限制暂时不可用）
"""

import os
from typing import Optional
from gmssl import sm4
import base64


class SM4Cipher:
    """SM4加解密器类"""
    
    def __init__(self, key: Optional[bytes] = None):
        """
        初始化SM4加密器
        
        Args:
            key: 16字节的SM4密钥，如果为None则自动生成
        """
        if key is None:
            self.key = self.generate_key()
        else:
            if len(key) != 16:
                raise ValueError("SM4密钥必须是16字节长度")
            self.key = key
        
        # 创建SM4实例
        self.sm4_crypt = sm4.CryptSM4()
        # 转换密钥为list格式（gmssl要求）
        self.key_list = list(self.key)
    
    @staticmethod
    def generate_key() -> bytes:
        """
        生成随机的16字节SM4密钥
        
        Returns:
            16字节的随机密钥
        """
        return os.urandom(16)
    
    def _pad_data(self, data: bytes) -> bytes:
        """
        对数据进行PKCS7填充
        
        Args:
            data: 需要填充的数据
            
        Returns:
            填充后的数据
        """
        block_size = 16  # SM4块大小是128位(16字节)
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """
        移除PKCS7填充
        
        Args:
            padded_data: 填充的数据
            
        Returns:
            移除填充后的原始数据
        """
        if len(padded_data) == 0:
            raise ValueError("数据为空")
        
        padding_length = padded_data[-1]
        if padding_length > 16 or padding_length == 0:
            raise ValueError("无效的填充")
        
        # 验证填充
        for i in range(padding_length):
            if padded_data[-(i+1)] != padding_length:
                raise ValueError("无效的填充")
        
        return padded_data[:-padding_length]
    
    def encrypt(self, plaintext: str, mode: str = 'ECB') -> dict:
        """
        加密明文
        
        Args:
            plaintext: 要加密的明文字符串
            mode: 加密模式，目前仅支持 'ECB'
            
        Returns:
            包含加密结果的字典
        """
        # 转换为字节
        data = plaintext.encode('utf-8')
        
        mode_upper = mode.upper()
        
        if mode_upper == 'ECB':
            # ECB模式
            self.sm4_crypt.set_key(self.key_list, sm4.SM4_ENCRYPT)
            
            # 填充数据
            padded_data = self._pad_data(data)
            
            # 转换为list格式（gmssl要求）
            data_list = list(padded_data)
            
            # ECB加密
            encrypted_list = self.sm4_crypt.crypt_ecb(data_list)
            ciphertext = bytes(encrypted_list)
            
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'mode': 'ECB'
            }
        
        elif mode_upper == 'CBC':
            # CBC模式暂时不支持，由于gmssl库的限制
            raise ValueError("CBC模式暂时不可用，请使用ECB模式或考虑其他SM4实现库")
        
        else:
            raise ValueError(f"不支持的加密模式: {mode}")
    
    def decrypt(self, encrypted_data: dict) -> str:
        """
        解密密文
        
        Args:
            encrypted_data: 包含加密数据的字典
            
        Returns:
            解密后的明文字符串
        """
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        mode = encrypted_data['mode']
        
        if mode == 'ECB':
            # ECB模式解密
            self.sm4_crypt.set_key(self.key_list, sm4.SM4_DECRYPT)
            
            # 转换为list格式（gmssl要求）
            ciphertext_list = list(ciphertext)
            
            # ECB解密
            decrypted_list = self.sm4_crypt.crypt_ecb(ciphertext_list)
            
            # 转换回bytes并只取有效长度（gmssl可能返回更长的数据）
            decrypted_bytes = bytes(decrypted_list[:len(ciphertext)])
            
            # 移除填充
            unpadded_data = self._unpad_data(decrypted_bytes)
            
        elif mode == 'CBC':
            # CBC模式暂时不支持
            raise ValueError("CBC模式暂时不可用")
            
        else:
            raise ValueError(f"不支持的解密模式: {mode}")
        
        return unpadded_data.decode('utf-8')
    
    def encrypt_file(self, input_file_path: str, output_file_path: str, 
                    mode: str = 'ECB') -> dict:
        """
        加密文件
        
        Args:
            input_file_path: 输入文件路径
            output_file_path: 输出文件路径
            mode: 加密模式
            
        Returns:
            包含加密信息的字典
        """
        with open(input_file_path, 'rb') as f:
            data = f.read()
        
        mode_upper = mode.upper()
        
        if mode_upper == 'ECB':
            # ECB模式
            self.sm4_crypt.set_key(self.key_list, sm4.SM4_ENCRYPT)
            
            # 填充数据
            padded_data = self._pad_data(data)
            
            # 转换为list格式（gmssl要求）
            data_list = list(padded_data)
            
            # ECB加密
            encrypted_list = self.sm4_crypt.crypt_ecb(data_list)
            ciphertext = bytes(encrypted_list)
            
            with open(output_file_path, 'wb') as f:
                f.write(ciphertext)
            
            return {
                'mode': 'ECB',
                'output_file': output_file_path
            }
            
        elif mode_upper == 'CBC':
            # CBC模式暂时不支持
            raise ValueError("CBC模式暂时不可用，请使用ECB模式")
        
        else:
            raise ValueError(f"不支持的加密模式: {mode}")
    
    def decrypt_file(self, input_file_path: str, output_file_path: str, 
                    encryption_info: dict) -> str:
        """
        解密文件
        
        Args:
            input_file_path: 加密文件路径
            output_file_path: 解密输出文件路径
            encryption_info: 加密时返回的信息字典
            
        Returns:
            输出文件路径
        """
        with open(input_file_path, 'rb') as f:
            ciphertext = f.read()
        
        mode = encryption_info['mode']
        
        if mode == 'ECB':
            # ECB模式解密
            self.sm4_crypt.set_key(self.key_list, sm4.SM4_DECRYPT)
            
            # 转换为list格式（gmssl要求）
            ciphertext_list = list(ciphertext)
            
            # ECB解密
            decrypted_list = self.sm4_crypt.crypt_ecb(ciphertext_list)
            
            # 转换回bytes并只取有效长度
            decrypted_bytes = bytes(decrypted_list[:len(ciphertext)])
            
            # 移除填充
            unpadded_data = self._unpad_data(decrypted_bytes)
            
        elif mode == 'CBC':
            # CBC模式暂时不支持
            raise ValueError("CBC模式暂时不可用")
            
        else:
            raise ValueError(f"不支持的解密模式: {mode}")
        
        with open(output_file_path, 'wb') as f:
            f.write(unpadded_data)
        
        return output_file_path
    
    def get_key_base64(self) -> str:
        """
        获取Base64编码的密钥
        
        Returns:
            Base64编码的密钥字符串
        """
        return base64.b64encode(self.key).decode('utf-8')
    
    @classmethod
    def from_key_base64(cls, key_base64: str) -> 'SM4Cipher':
        """
        从Base64编码的密钥创建SM4加密器
        
        Args:
            key_base64: Base64编码的密钥字符串
            
        Returns:
            SM4Cipher实例
        """
        key = base64.b64decode(key_base64)
        return cls(key)
    
    def get_key_info(self) -> dict:
        """
        获取密钥信息
        
        Returns:
            包含密钥信息的字典
        """
        return {
            'algorithm': 'SM4',
            'key_size': len(self.key),
            'key_base64': self.get_key_base64()
        } 