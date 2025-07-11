"""
DES/3DES加解密实现

使用cryptography库实现3DES算法的加密和解密功能
注意：由于DES算法已被认为不安全，这里使用3DES作为替代
"""

import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64


class DESCipher:
    """3DES加解密器类"""
    
    def __init__(self, key: Optional[bytes] = None):
        """
        初始化3DES加密器
        
        Args:
            key: 24字节的3DES密钥，如果为None则自动生成
        """
        if key is None:
            self.key = self.generate_key()
        else:
            if len(key) != 24:
                raise ValueError("3DES密钥必须是24字节长度")
            self.key = key
    
    @staticmethod
    def generate_key() -> bytes:
        """
        生成随机的24字节3DES密钥
        
        Returns:
            24字节的随机密钥
        """
        return os.urandom(24)
    
    def _pad_data(self, data: bytes) -> bytes:
        """
        对数据进行PKCS7填充
        
        Args:
            data: 需要填充的数据
            
        Returns:
            填充后的数据
        """
        padder = padding.PKCS7(64).padder()  # 3DES块大小是64位(8字节)
        padded_data = padder.update(data)
        padded_data += padder.finalize()
        return padded_data
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """
        移除PKCS7填充
        
        Args:
            padded_data: 填充的数据
            
        Returns:
            移除填充后的原始数据
        """
        unpadder = padding.PKCS7(64).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()
        return data
    
    def encrypt(self, plaintext: str, mode: str = 'CBC') -> dict:
        """
        加密明文
        
        Args:
            plaintext: 要加密的明文字符串
            mode: 加密模式，支持 'CBC', 'ECB'
            
        Returns:
            包含加密结果的字典，包含ciphertext和iv(如果使用CBC模式)
        """
        # 转换为字节
        data = plaintext.encode('utf-8')
        
        # 填充数据
        padded_data = self._pad_data(data)
        
        # 根据模式创建加密器
        if mode.upper() == 'CBC':
            iv = os.urandom(8)  # 3DES块大小是8字节
            cipher = Cipher(
                TripleDES(self.key), 
                modes.CBC(iv), 
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'mode': 'CBC'
            }
        
        elif mode.upper() == 'ECB':
            cipher = Cipher(
                TripleDES(self.key), 
                modes.ECB(), 
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'mode': 'ECB'
            }
        
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
        
        if mode == 'CBC':
            iv = base64.b64decode(encrypted_data['iv'])
            cipher = Cipher(
                TripleDES(self.key), 
                modes.CBC(iv), 
                backend=default_backend()
            )
            
        elif mode == 'ECB':
            cipher = Cipher(
                TripleDES(self.key), 
                modes.ECB(), 
                backend=default_backend()
            )
            
        else:
            raise ValueError(f"不支持的解密模式: {mode}")
        
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 移除填充
        plaintext = self._unpad_data(padded_plaintext)
        
        return plaintext.decode('utf-8')
    
    def encrypt_file(self, input_file_path: str, output_file_path: str, mode: str = 'CBC') -> dict:
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
        
        # 填充数据
        padded_data = self._pad_data(data)
        
        if mode.upper() == 'CBC':
            iv = os.urandom(8)
            cipher = Cipher(
                TripleDES(self.key), 
                modes.CBC(iv), 
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            with open(output_file_path, 'wb') as f:
                f.write(ciphertext)
            
            return {
                'iv': base64.b64encode(iv).decode('utf-8'),
                'mode': 'CBC',
                'output_file': output_file_path
            }
            
        elif mode.upper() == 'ECB':
            cipher = Cipher(
                TripleDES(self.key), 
                modes.ECB(), 
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            with open(output_file_path, 'wb') as f:
                f.write(ciphertext)
            
            return {
                'mode': 'ECB',
                'output_file': output_file_path
            }
    
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
        
        if mode == 'CBC':
            iv = base64.b64decode(encryption_info['iv'])
            cipher = Cipher(
                TripleDES(self.key), 
                modes.CBC(iv), 
                backend=default_backend()
            )
            
        elif mode == 'ECB':
            cipher = Cipher(
                TripleDES(self.key), 
                modes.ECB(), 
                backend=default_backend()
            )
        
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 移除填充
        plaintext = self._unpad_data(padded_plaintext)
        
        with open(output_file_path, 'wb') as f:
            f.write(plaintext)
        
        return output_file_path
    
    def get_key_base64(self) -> str:
        """
        获取Base64编码的密钥
        
        Returns:
            Base64编码的密钥字符串
        """
        return base64.b64encode(self.key).decode('utf-8')
    
    @classmethod
    def from_key_base64(cls, key_base64: str) -> 'DESCipher':
        """
        从Base64编码的密钥创建DESCipher实例
        
        Args:
            key_base64: Base64编码的密钥
            
        Returns:
            DESCipher实例
        """
        key = base64.b64decode(key_base64)
        return cls(key) 