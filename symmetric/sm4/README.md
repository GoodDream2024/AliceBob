# SM4 加解密模块

基于 GM/T 0002-2012 标准的国密 SM4 分组密码算法实现，使用 `gmssl` 库提供高效安全的 SM4 加解密功能。

## 特性

- ✅ 完整的 SM4 加解密支持
- ✅ 支持 ECB 和 CBC 加密模式
- ✅ 字符串和文件加解密
- ✅ 自动密钥生成和管理
- ✅ Base64 编码处理
- ✅ PKCS7 填充算法
- ✅ 国密标准兼容

## 快速开始

### 基本使用

```python
from symmetric.sm4 import SM4Cipher

# 创建 SM4 加密器（自动生成密钥）
cipher = SM4Cipher()

# 加密文本
plaintext = "Hello SM4!"
encrypted = cipher.encrypt(plaintext, mode='ECB')
print(f"加密结果: {encrypted}")

# 解密文本
decrypted = cipher.decrypt(encrypted)
print(f"解密结果: {decrypted}")
```

### 使用自定义密钥

```python
# 使用 16 字节自定义密钥
custom_key = b'1234567890123456'
cipher = SM4Cipher(custom_key)

# 或从 Base64 字符串创建
key_base64 = 'MTIzNDU2Nzg5MDEyMzQ1Ng=='
cipher = SM4Cipher.from_key_base64(key_base64)
```

## 支持的加密模式

### ECB 模式（电子密码本模式）

```python
# ECB 模式加密
encrypted = cipher.encrypt("Hello World", mode='ECB')
decrypted = cipher.decrypt(encrypted)
```

**特点：**
- 相同明文块产生相同密文块
- 不需要初始化向量（IV）
- 适合短消息加密

### CBC 模式（密码块链接模式）

```python
# CBC 模式加密
encrypted = cipher.encrypt("Hello World", mode='CBC')
decrypted = cipher.decrypt(encrypted)
```

**特点：**
- 使用随机初始化向量（IV）
- 相同明文产生不同密文
- 更高的安全性
- 推荐用于大多数场景

## 文件加解密

```python
# 加密文件
encryption_info = cipher.encrypt_file(
    'input.txt', 
    'encrypted.bin', 
    mode='CBC'
)

# 解密文件
cipher.decrypt_file(
    'encrypted.bin', 
    'output.txt', 
    encryption_info
)
```

## 密钥管理

```python
# 获取密钥信息
key_info = cipher.get_key_info()
print(key_info)
# 输出: {'algorithm': 'SM4', 'key_size': 16, 'key_base64': '...'}

# 导出密钥
key_base64 = cipher.get_key_base64()

# 导入密钥
new_cipher = SM4Cipher.from_key_base64(key_base64)
```

## API 参考

### SM4Cipher 类

#### 构造函数

```python
SM4Cipher(key: Optional[bytes] = None)
```

- `key`: 16 字节的 SM4 密钥，为 None 时自动生成

#### 实例方法

##### encrypt(plaintext, mode='ECB')

加密字符串。

**参数：**
- `plaintext` (str): 要加密的明文
- `mode` (str): 加密模式，'ECB' 或 'CBC'

**返回：**
- `dict`: 包含加密结果的字典

##### decrypt(encrypted_data)

解密字符串。

**参数：**
- `encrypted_data` (dict): encrypt() 返回的加密数据

**返回：**
- `str`: 解密后的明文

##### encrypt_file(input_path, output_path, mode='ECB')

加密文件。

**参数：**
- `input_path` (str): 输入文件路径
- `output_path` (str): 输出文件路径
- `mode` (str): 加密模式

**返回：**
- `dict`: 包含加密信息的字典

##### decrypt_file(input_path, output_path, encryption_info)

解密文件。

**参数：**
- `input_path` (str): 加密文件路径
- `output_path` (str): 解密输出路径
- `encryption_info` (dict): encrypt_file() 返回的加密信息

**返回：**
- `str`: 输出文件路径

#### 静态方法

##### generate_key()

生成随机的 16 字节 SM4 密钥。

**返回：**
- `bytes`: 随机密钥

##### from_key_base64(key_base64)

从 Base64 编码的密钥创建 SM4Cipher 实例。

**参数：**
- `key_base64` (str): Base64 编码的密钥

**返回：**
- `SM4Cipher`: 新的加密器实例

## 安全建议

1. **密钥管理**：
   - 使用安全的随机数生成器生成密钥
   - 密钥应安全存储，避免硬编码
   - 定期更换密钥

2. **模式选择**：
   - 大多数情况下推荐使用 CBC 模式
   - ECB 模式仅适用于短消息或特殊场景

3. **数据处理**：
   - 敏感数据处理后及时清理内存
   - 验证解密数据的完整性

## 错误处理

模块会在以下情况抛出异常：

- `ValueError`: 密钥长度不正确（必须是 16 字节）
- `ValueError`: 不支持的加密模式
- `ValueError`: 无效的填充数据

## 示例代码

运行 `example.py` 查看完整的使用示例：

```bash
python symmetric/sm4/example.py
```

## 技术规范

- **算法标准**: GM/T 0002-2012
- **密钥长度**: 128 位（16 字节）
- **块大小**: 128 位（16 字节）
- **填充方式**: PKCS7
- **依赖库**: gmssl >= 3.2.2

## 许可证

本模块遵循项目的整体许可证。 