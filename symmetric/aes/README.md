# AES加解密模块

基于cryptography库实现的AES（Advanced Encryption Standard）加解密功能模块。

## 特性

- 🔐 支持AES-128、AES-192、AES-256三种密钥长度
- 🛡️ 支持CBC、ECB、GCM三种加密模式
- 📄 支持文本和文件加解密
- 🔑 自动密钥生成和管理
- 🔗 Base64编码的密钥共享
- ✅ PKCS7填充（CBC/ECB模式）
- 🔒 认证加密（GCM模式）

## 快速开始

### 基本文本加解密

```python
from symmetric.aes import AESCipher

# 创建AES加密器（默认AES-256）
aes = AESCipher()

# 加密文本
plaintext = "这是一个秘密消息"
encrypted = aes.encrypt(plaintext, mode='GCM')  # 推荐使用GCM模式
print(f"加密结果: {encrypted}")

# 解密文本
decrypted = aes.decrypt(encrypted)
print(f"解密结果: {decrypted}")
```

### 选择不同的AES密钥长度

```python
# AES-128 (16字节密钥)
aes128 = AESCipher(key_size=16)

# AES-192 (24字节密钥)
aes192 = AESCipher(key_size=24)

# AES-256 (32字节密钥，默认，最安全)
aes256 = AESCipher(key_size=32)

# 查看密钥信息
key_info = aes256.get_key_info()
print(f"算法: {key_info['algorithm']}")
print(f"密钥长度: {key_info['key_size_bits']}位")
```

### 使用自定义密钥

```python
# 使用32字节的自定义密钥（AES-256）
custom_key = b'abcdefghijklmnopqrstuvwxyz123456'  # 32字节
aes = AESCipher(custom_key)

encrypted = aes.encrypt("使用自定义密钥")
decrypted = aes.decrypt(encrypted)
```

### 密钥共享

```python
# 发送方
sender = AESCipher()
shared_key = sender.get_key_base64()  # 获取Base64编码的密钥

# 接收方
receiver = AESCipher.from_key_base64(shared_key)

# 发送方加密
encrypted_msg = sender.encrypt("机密消息", mode='GCM')

# 接收方解密
decrypted_msg = receiver.decrypt(encrypted_msg)
```

### 文件加解密

```python
aes = AESCipher()

# 加密文件
encryption_info = aes.encrypt_file('input.txt', 'encrypted.bin', mode='GCM')

# 解密文件
aes.decrypt_file('encrypted.bin', 'decrypted.txt', encryption_info)
```

## API参考

### AESCipher类

#### 构造函数
- `AESCipher(key=None, key_size=32)`: 创建AES加密器
  - `key`: 可选的AES密钥，如果为None则自动生成
  - `key_size`: 密钥长度（字节），16=AES-128, 24=AES-192, 32=AES-256

#### 主要方法

- `encrypt(plaintext, mode='CBC')`: 加密文本
  - `plaintext`: 要加密的字符串
  - `mode`: 加密模式，支持'CBC'、'ECB'、'GCM'
  - 返回: 包含加密数据的字典

- `decrypt(encrypted_data)`: 解密文本
  - `encrypted_data`: 加密方法返回的字典
  - 返回: 解密后的字符串

- `encrypt_file(input_path, output_path, mode='CBC')`: 加密文件
- `decrypt_file(input_path, output_path, encryption_info)`: 解密文件

- `get_key_base64()`: 获取Base64编码的密钥
- `get_key_info()`: 获取密钥详细信息
- `from_key_base64(key_base64)`: 从Base64密钥创建实例（类方法）

#### 静态方法

- `generate_key(key_size=32)`: 生成指定长度的随机密钥

## 加密模式

### GCM模式 🌟（强烈推荐）
- **认证加密**: 同时提供机密性和完整性保护
- **安全性最高**: 能检测数据是否被篡改
- **现代标准**: 广泛用于TLS、VPN等安全协议
- **自动验证**: 解密时自动验证数据完整性

```python
encrypted = aes.encrypt("消息", mode='GCM')
# 返回: {'ciphertext': '...', 'iv': '...', 'tag': '...', 'mode': 'GCM'}
```

### CBC模式 ✅（推荐）
- **链式加密**: 使用初始化向量(IV)，安全性好
- **随机性**: 相同明文产生不同密文
- **需要填充**: 使用PKCS7填充
- **广泛支持**: 传统加密的标准选择

```python
encrypted = aes.encrypt("消息", mode='CBC')
# 返回: {'ciphertext': '...', 'iv': '...', 'mode': 'CBC'}
```

### ECB模式 ⚠️（不推荐）
- **简单模式**: 不使用IV，实现最简单
- **安全风险**: 相同明文块产生相同密文块
- **仅限测试**: 不推荐用于敏感数据
- **需要填充**: 使用PKCS7填充

```python
encrypted = aes.encrypt("消息", mode='ECB')
# 返回: {'ciphertext': '...', 'mode': 'ECB'}
```

## 密钥长度对比

| 算法     | 密钥长度 | 安全性 | 性能   | 推荐用途           |
|----------|----------|--------|--------|--------------------|
| AES-128  | 128位    | 高     | 最快   | 一般应用           |
| AES-192  | 192位    | 很高   | 中等   | 敏感数据           |
| AES-256  | 256位    | 极高   | 较慢   | 最高安全要求       |

## 安全最佳实践

### 1. 模式选择
```python
# ✅ 推荐：使用GCM模式（认证加密）
aes.encrypt(data, mode='GCM')

# ✅ 可以：使用CBC模式
aes.encrypt(data, mode='CBC')

# ❌ 避免：不要使用ECB模式处理敏感数据
```

### 2. 密钥管理
```python
# ✅ 安全的密钥生成
aes = AESCipher()  # 自动生成强随机密钥

# ✅ 安全的密钥共享
shared_key = aes.get_key_base64()  # 通过安全通道传输

# ❌ 避免硬编码密钥
# aes = AESCipher(b'hardcoded_key_bad_practice')
```

### 3. 数据处理
```python
# ✅ 处理敏感数据后清理
plaintext = "sensitive data"
encrypted = aes.encrypt(plaintext, mode='GCM')
del plaintext  # 清理敏感数据

# ✅ 验证解密结果
try:
    decrypted = aes.decrypt(encrypted)
    print("解密成功")
except Exception as e:
    print(f"解密失败: {e}")
```

## 性能考虑

### 大文件处理
- 对于大文件，建议使用文件加解密方法
- GCM模式在大数据量时性能略低于CBC
- AES-256比AES-128慢约30%，但安全性更高

### 内存使用
- 文件加解密会将整个文件读入内存
- 对于极大文件，考虑分块处理（可在此基础上扩展）

## 示例运行

查看完整示例：

```bash
cd symmetric/aes
python example.py
```

## 与其他算法对比

| 特性       | AES        | DES/3DES   |
|------------|------------|------------|
| 安全性     | 极高       | 低/中等    |
| 密钥长度   | 128-256位  | 64/192位   |
| 块大小     | 128位      | 64位       |
| 性能       | 快         | 较慢       |
| 标准状态   | 现行标准   | 已弃用/过渡 |

## 依赖

- cryptography >= 45.0.5
- Python >= 3.13

## 常见问题

### Q: 选择哪种密钥长度？
A: 对于大多数应用，AES-256提供最高安全性。如果性能敏感且安全要求不是极高，可以选择AES-128。

### Q: 选择哪种加密模式？
A: 优先选择GCM模式（认证加密），其次是CBC模式。避免使用ECB模式。

### Q: 如何安全地存储密钥？
A: 不要硬编码密钥，使用密钥管理系统或安全的配置文件，通过环境变量或安全通道传递。

### Q: GCM模式的tag是什么？
A: tag是认证标签，用于验证数据完整性。解密时会自动验证，如果数据被篡改会抛出异常。 