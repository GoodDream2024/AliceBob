"""
AES加解密实现

使用cryptography库实现AES算法的加密和解密功能
支持AES-128、AES-192、AES-256和多种加密模式
"""

import os
from typing import Optional, Literal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64


KeySize = Literal[16, 24, 32]  # AES-128, AES-192, AES-256


class AESCipher:
    """AES加解密器类"""
    
    def __init__(self, key: Optional[bytes] = None, key_size: KeySize = 32):
        """
        初始化AES加密器
        
        Args:
            key: AES密钥，如果为None则自动生成
            key_size: 密钥长度，16=AES-128, 24=AES-192, 32=AES-256（默认）
        """
        if key is None:
            self.key = self.generate_key(key_size)
        else:
            if len(key) not in [16, 24, 32]:
                raise ValueError("AES密钥长度必须是16、24或32字节")
            self.key = key
        
        self.key_size = len(self.key)
    
    @staticmethod
    def generate_key(key_size: KeySize = 32) -> bytes:
        """
        生成随机的AES密钥
        
        Args:
            key_size: 密钥长度（字节），16=AES-128, 24=AES-192, 32=AES-256
            
        Returns:
            指定长度的随机密钥
        """
        if key_size not in [16, 24, 32]:
            raise ValueError("密钥长度必须是16、24或32字节")
        return os.urandom(key_size)
    
    def _pad_data(self, data: bytes) -> bytes:
        """
        对数据进行PKCS7填充
        
        Args:
            data: 需要填充的数据
            
        Returns:
            填充后的数据
        """
        padder = padding.PKCS7(128).padder()  # AES块大小是128位(16字节)
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
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()
        return data
    
    def encrypt(self, plaintext: str, mode: str = 'CBC') -> dict:
        """
        加密明文
        
        Args:
            plaintext: 要加密的明文字符串
            mode: 加密模式，支持 'CBC', 'ECB', 'GCM'
            
        Returns:
            包含加密结果的字典
        """
        # 转换为字节
        data = plaintext.encode('utf-8')
        
        mode_upper = mode.upper()
        
        if mode_upper == 'GCM':
            # GCM模式自带认证，不需要填充
            iv = os.urandom(12)  # GCM推荐12字节IV
            cipher = Cipher(
                algorithms.AES(self.key), 
                modes.GCM(iv), 
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
                'mode': 'GCM'
            }
        
        else:
            # CBC和ECB模式需要填充
            padded_data = self._pad_data(data)
            
            if mode_upper == 'CBC':
                iv = os.urandom(16)  # AES块大小是16字节
                cipher = Cipher(
                    algorithms.AES(self.key), 
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
            
            elif mode_upper == 'ECB':
                cipher = Cipher(
                    algorithms.AES(self.key), 
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
        
        if mode == 'GCM':
            iv = base64.b64decode(encrypted_data['iv'])
            tag = base64.b64decode(encrypted_data['tag'])
            cipher = Cipher(
                algorithms.AES(self.key), 
                modes.GCM(iv, tag), 
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
        elif mode == 'CBC':
            iv = base64.b64decode(encrypted_data['iv'])
            cipher = Cipher(
                algorithms.AES(self.key), 
                modes.CBC(iv), 
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = self._unpad_data(padded_plaintext)
            
        elif mode == 'ECB':
            cipher = Cipher(
                algorithms.AES(self.key), 
                modes.ECB(), 
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = self._unpad_data(padded_plaintext)
            
        else:
            raise ValueError(f"不支持的解密模式: {mode}")
        
        return plaintext.decode('utf-8')
    
    def encrypt_file(self, input_file_path: str, output_file_path: str, 
                    mode: str = 'CBC') -> dict:
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
        
        if mode_upper == 'GCM':
            iv = os.urandom(12)
            cipher = Cipher(
                algorithms.AES(self.key), 
                modes.GCM(iv), 
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            with open(output_file_path, 'wb') as f:
                f.write(ciphertext)
            
            return {
                'iv': base64.b64encode(iv).decode('utf-8'),
                'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
                'mode': 'GCM',
                'output_file': output_file_path
            }
        
        else:
            # 填充数据
            padded_data = self._pad_data(data)
            
            if mode_upper == 'CBC':
                iv = os.urandom(16)
                cipher = Cipher(
                    algorithms.AES(self.key), 
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
                
            elif mode_upper == 'ECB':
                cipher = Cipher(
                    algorithms.AES(self.key), 
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
        
        if mode == 'GCM':
            iv = base64.b64decode(encryption_info['iv'])
            tag = base64.b64decode(encryption_info['tag'])
            cipher = Cipher(
                algorithms.AES(self.key), 
                modes.GCM(iv, tag), 
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
        elif mode == 'CBC':
            iv = base64.b64decode(encryption_info['iv'])
            cipher = Cipher(
                algorithms.AES(self.key), 
                modes.CBC(iv), 
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = self._unpad_data(padded_plaintext)
            
        elif mode == 'ECB':
            cipher = Cipher(
                algorithms.AES(self.key), 
                modes.ECB(), 
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
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
    def from_key_base64(cls, key_base64: str) -> 'AESCipher':
        """
        从Base64编码的密钥创建AESCipher实例
        
        Args:
            key_base64: Base64编码的密钥
            
        Returns:
            AESCipher实例
        """
        key = base64.b64decode(key_base64.encode('utf-8'))
        return cls(key)
    
    def get_key_info(self) -> dict:
        """
        获取密钥信息
        
        Returns:
            包含密钥信息的字典
        """
        key_sizes = {16: 'AES-128', 24: 'AES-192', 32: 'AES-256'}
        return {
            'algorithm': key_sizes[self.key_size],
            'key_size_bytes': self.key_size,
            'key_size_bits': self.key_size * 8,
            'key_base64': self.get_key_base64()
        } 