"""
SM4对称加密模块

基于GM/T 0002-2012标准的SM4分组密码算法实现
使用gmssl库提供国密SM4加解密功能
"""

from .sm4_cipher import SM4Cipher

__all__ = ['SM4Cipher'] 