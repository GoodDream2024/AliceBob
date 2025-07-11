# DES加解密模块

基于cryptography库实现的3DES加解密功能模块。

## 重要说明

由于传统DES算法已被认为不安全，本模块实际使用**3DES（Triple DES）**算法，它是DES的安全增强版本。

## 特性

- 支持CBC和ECB两种加密模式
- 支持文本和文件加解密
- 自动密钥生成和管理
- Base64编码的密钥共享
- PKCS7填充

## 快速开始

### 基本文本加解密

```python
from symmetric.des import DESCipher

# 创建DES加密器（自动生成密钥）
des = DESCipher()

# 加密文本
plaintext = "这是一个秘密消息"
encrypted = des.encrypt(plaintext, mode='CBC')
print(f"加密结果: {encrypted}")

# 解密文本
decrypted = des.decrypt(encrypted)
print(f"解密结果: {decrypted}")
```

### 使用自定义密钥

```python
# 使用24字节的自定义密钥
custom_key = b'abcdefghijklmnopqrstuvwx'  # 24字节
des = DESCipher(custom_key)

encrypted = des.encrypt("使用自定义密钥")
decrypted = des.decrypt(encrypted)
```

### 密钥共享

```python
# 发送方
sender = DESCipher()
shared_key = sender.get_key_base64()  # 获取Base64编码的密钥

# 接收方
receiver = DESCipher.from_key_base64(shared_key)

# 发送方加密
encrypted_msg = sender.encrypt("机密消息")

# 接收方解密
decrypted_msg = receiver.decrypt(encrypted_msg)
```

### 文件加解密

```python
des = DESCipher()

# 加密文件
encryption_info = des.encrypt_file('input.txt', 'encrypted.bin', mode='CBC')

# 解密文件
des.decrypt_file('encrypted.bin', 'decrypted.txt', encryption_info)
```

## API参考

### DESCipher类

#### 构造函数
- `DESCipher(key=None)`: 创建DES加密器
  - `key`: 可选的24字节密钥，如果为None则自动生成

#### 主要方法

- `encrypt(plaintext, mode='CBC')`: 加密文本
  - `plaintext`: 要加密的字符串
  - `mode`: 加密模式，支持'CBC'或'ECB'
  - 返回: 包含加密数据的字典

- `decrypt(encrypted_data)`: 解密文本
  - `encrypted_data`: 加密方法返回的字典
  - 返回: 解密后的字符串

- `encrypt_file(input_path, output_path, mode='CBC')`: 加密文件
- `decrypt_file(input_path, output_path, encryption_info)`: 解密文件

- `get_key_base64()`: 获取Base64编码的密钥
- `from_key_base64(key_base64)`: 从Base64密钥创建实例（类方法）

#### 静态方法

- `generate_key()`: 生成24字节随机密钥

## 加密模式

### CBC模式（推荐）
- 使用初始化向量(IV)，更安全
- 相同明文产生不同密文
- 需要保存IV用于解密

### ECB模式
- 不使用IV，相对简单
- 相同明文块产生相同密文块
- 安全性较低，不推荐用于敏感数据

## 安全注意事项

1. **密钥管理**: 妥善保管密钥，不要在代码中硬编码
2. **模式选择**: 建议使用CBC模式而非ECB模式
3. **密钥长度**: 使用24字节密钥（192位）
4. **传输安全**: 通过安全通道传输密钥和加密数据

## 示例运行

查看 `example.py` 文件获取完整的使用示例：

```bash
cd symmetric/des
python example.py
```

## 依赖

- cryptography >= 45.0.5
- Python >= 3.13 