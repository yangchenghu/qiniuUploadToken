#!/usr/bin/python
# -*- coding: utf-8 -*-

import hmac
import time
from hashlib import sha1
from base64 import urlsafe_b64encode, urlsafe_b64decode

try:
	import zlib
	binascii = zlib
except ImportError:
	zlib = None
	import binascii

import sys

try:
    import simplejson as json
except (ImportError, SyntaxError):
    # simplejson does not support Python 3.2, it thows a SyntaxError
    # because of u'...' Unicode literals.
    import json  # noqa


# -------
# Pythons
# -------

_ver = sys.version_info

#: Python 2.x?
is_py2 = (_ver[0] == 2)

#: Python 3.x?
is_py3 = (_ver[0] == 3)


# ---------
# Specifics
# ---------

if is_py2:
    from urlparse import urlparse  # noqa
    import StringIO
    StringIO = BytesIO = StringIO.StringIO

    builtin_str = str
    bytes = str
    str = unicode  # noqa
    basestring = basestring  # noqa
    numeric_types = (int, long, float)  # noqa

    def b(data):
        return data

    def s(data):
        return data

    def u(data):
        return unicode(data, 'unicode_escape')  # noqa

elif is_py3:
    from urllib.parse import urlparse  # noqa
    import io
    StringIO = io.StringIO
    BytesIO = io.BytesIO

    builtin_str = str
    str = str
    bytes = bytes
    basestring = (str, bytes)
    numeric_types = (int, float)

    def b(data):
        if isinstance(data, str):
            return data.encode('utf-8')
        return data

    def s(data):
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return data

    def u(data):
        return data


def urlsafe_base64_encode(data):
	"""urlsafe的base64编码:

	对提供的数据进行urlsafe的base64编码。规格参考：
	http://developer.qiniu.com/docs/v6/api/overview/appendix.html#urlsafe-base64

	Args:
		data: 待编码的数据，一般为字符串

	Returns:
		编码后的字符串
	"""
	ret = urlsafe_b64encode(b(data))
	return s(ret)


def urlsafe_base64_decode(data):
	"""urlsafe的base64解码:

	对提供的urlsafe的base64编码的数据进行解码

	Args:
		data: 待解码的数据，一般为字符串

	Returns:
		解码后的字符串。
	"""
	ret = urlsafe_b64decode(s(data))
	return ret


def file_crc32(filePath):
	"""计算文件的crc32检验码:

	Args:
		filePath: 待计算校验码的文件路径

	Returns:
		文件内容的crc32校验码。
	"""
	crc = 0
	with open(filePath, 'rb') as f:
		for block in _file_iter(f, _BLOCK_SIZE):
			crc = binascii.crc32(block, crc) & 0xFFFFFFFF
	return crc


def crc32(data):
	"""计算输入流的crc32检验码:

	Args:
		data: 待计算校验码的字符流

	Returns:
		输入流的crc32校验码。
	"""
	return binascii.crc32(b(data)) & 0xffffffff


def _file_iter(input_stream, size, offset=0):
	"""读取输入流:

	Args:
		input_stream: 待读取文件的二进制流
		size:         二进制流的大小

	Raises:
		IOError: 文件流读取失败
	"""
	input_stream.seek(offset)
	d = input_stream.read(size)
	while d:
		yield d
		d = input_stream.read(size)


def _sha1(data):
	"""单块计算hash:

	Args:
		data: 待计算hash的数据

	Returns:
		输入数据计算的hash值
	"""
	h = sha1()
	h.update(data)
	return h.digest()


def etag_stream(input_stream):
	"""计算输入流的etag:

	etag规格参考 http://developer.qiniu.com/docs/v6/api/overview/appendix.html#qiniu-etag

	Args:
		input_stream: 待计算etag的二进制流

	Returns:
		输入流的etag值
	"""
	array = [_sha1(block) for block in _file_iter(input_stream, _BLOCK_SIZE)]
	if len(array) == 1:
		data = array[0]
		prefix = b('\x16')
	else:
		sha1_str = b('').join(array)
		data = _sha1(sha1_str)
		prefix = b('\x96')
	return urlsafe_base64_encode(prefix + data)


def etag(filePath):
	"""计算文件的etag:

	Args:
		filePath: 待计算etag的文件路径

	Returns:
		输入文件的etag值
	"""
	with open(filePath, 'rb') as f:
		return etag_stream(f)


def entry(bucket, key):
	"""计算七牛API中的数据格式:

	entry规格参考 http://developer.qiniu.com/docs/v6/api/reference/data-formats.html

	Args:
		bucket: 待操作的空间名
		key:    待操作的文件名

	Returns:
		符合七牛API规格的数据格式
	"""
	if key is None:
		return urlsafe_base64_encode('{0}'.format(bucket))
	else:
		return urlsafe_base64_encode('{0}:{1}'.format(bucket, key))

# 上传策略，参数规格详见
# http://developer.qiniu.com/docs/v6/api/reference/security/put-policy.html
_policy_fields = set([
	'callbackUrl',       # 回调URL
	'callbackBody',      # 回调Body
	'callbackHost',      # 回调URL指定的Host
	'callbackBodyType',  # 回调Body的Content-Type
	'callbackFetchKey',  # 回调FetchKey模式开关

	'returnUrl',         # 上传端的303跳转URL
	'returnBody',        # 上传端简单反馈获取的Body

	'endUser',           # 回调时上传端标识
	'saveKey',           # 自定义资源名
	'insertOnly',        # 插入模式开关

	'detectMime',        # MimeType侦测开关
	'mimeLimit',         # MimeType限制
	'fsizeLimit',        # 上传文件大小限制

	'persistentOps',        # 持久化处理操作
	'persistentNotifyUrl',  # 持久化处理结果通知URL
	'persistentPipeline',   # 持久化处理独享队列
])

_deprecated_policy_fields = set([
	'asyncOps'
])

class Auth(object):
	'''七牛安全机制类

	该类主要内容是七牛上传凭证、下载凭证、管理凭证三种凭证的签名接口的实现，以及回调验证。

	Attributes:
		__access_key: 账号密钥对中的accessKey，详见 https://portal.qiniu.com/setting/key
		__secret_key: 账号密钥对重的secretKey，详见 https://portal.qiniu.com/setting/key
	'''

	def __init__(self, access_key, secret_key):
		"""初始化Auth类"""
		self.__checkKey(access_key, secret_key)
		self.__access_key = access_key
		self.__secret_key = b(secret_key)

	def __token(self, data):
		data = b(data)
		hashed = hmac.new(self.__secret_key, data, sha1)
		return urlsafe_base64_encode(hashed.digest())

	def token(self, data):
		return '{0}:{1}'.format(self.__access_key, self.__token(data))

	def token_with_data(self, data):
		data = urlsafe_base64_encode(data)
		return '{0}:{1}:{2}'.format(self.__access_key, self.__token(data), data)

	def token_of_request(self, url, body=None, content_type=None):
		"""带请求体的签名（本质上是管理凭证的签名）

		Args:
			url:          待签名请求的url
			body:         待签名请求的body
			content_type: 待签名请求的body的Content-Type

		Returns:
			管理凭证
		"""
		parsed_url = urlparse(url)
		query = parsed_url.query
		path = parsed_url.path
		data = path
		if query != '':
			data = ''.join([data, '?', query])
		data = ''.join([data, "\n"])

		if body:
			mimes = [
				'application/x-www-form-urlencoded'
			]
			if content_type in mimes:
				data += body

		return '{0}:{1}'.format(self.__access_key, self.__token(data))

	@staticmethod
	def __checkKey(access_key, secret_key):
		if not (access_key and secret_key):
			raise ValueError('invalid key')

	def private_download_url(self, url, expires=3600):
		"""生成私有资源下载链接

		Args:
			url:     私有空间资源的原始URL
			expires: 下载凭证有效期，默认为3600s

		Returns:
			私有资源的下载链接
		"""
		deadline = int(time.time()) + expires
		if '?' in url:
			url += '&'
		else:
			url += '?'
		url = '{0}e={1}'.format(url, str(deadline))

		token = self.token(url)
		return '{0}&token={1}'.format(url, token)

	def upload_token(self, bucket, key=None, expires=3600, policy=None, strict_policy=True):
		"""生成上传凭证

		Args:
			bucket:  上传的空间名
			key:     上传的文件名，默认为空
			expires: 上传凭证的过期时间，默认为3600s
			policy:  上传策略，默认为空

		Returns:
			上传凭证
		"""
		if bucket is None or bucket == '':
			raise ValueError('invalid bucket name')

		scope = bucket
		if key is not None:
			scope = '{0}:{1}'.format(bucket, key)

		args = dict(
			scope=scope,
			deadline=int(time.time()) + expires,
		)

		if policy is not None:
			self.__copy_policy(policy, args, strict_policy)

		return self.__upload_token(args)

	def __upload_token(self, policy):
		data = json.dumps(policy, separators=(',', ':'))
		return self.token_with_data(data)

	def verify_callback(self, origin_authorization, url, body, content_type='application/x-www-form-urlencoded'):
		"""回调验证

		Args:
			origin_authorization: 回调时请求Header中的Authorization字段
			url:                  回调请求的url
			body:                 回调请求的body
			content_type:         回调请求body的Content-Type

		Returns:
			返回true表示验证成功，返回false表示验证失败
		"""
		token = self.token_of_request(url, body, content_type)
		authorization = 'QBox {0}'.format(token)
		return origin_authorization == authorization

	@staticmethod
	def __copy_policy(policy, to, strict_policy):
		for k, v in policy.items():
			if k in _deprecated_policy_fields:
				raise ValueError(k + ' has deprecated')
			if (not strict_policy) or k in _policy_fields:
				to[k] = v


# if __name__ == '__main__':
# 	q = Auth("access_key", "secret_key")
# 	token = q.upload_token("bucket_name", "uploadfilename")
# 	print token


