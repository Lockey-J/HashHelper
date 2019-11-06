
using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace HashHelper
{
    /// <summary>
    /// 密码加密解密操作相关类
    /// </summary>
    public static class PassWordHelper
    {

        #region MD5 加密

        /// <summary>
        /// MD5加密
        /// </summary>
        public static string Md532(this string source)
        {
            if (string.IsNullOrEmpty(source))
            {
                return string.Empty;
            }
            Encoding mEncoding = Encoding.UTF8;
            MD5 mMD5 = MD5.Create();
            return HashAlgorithmBase(mMD5, source, mEncoding);
        }

        /// <summary>
        /// 加盐MD5加密
        /// </summary>
        public static string Md532Salt(this string source, string salt)
        {
            StringBuilder mSource = new StringBuilder();
            mSource.Append(source);
            mSource.Append(salt);
            return (string.IsNullOrEmpty(source) ? string.Empty : mSource.ToString().Md532());
        }

        #endregion

        #region SHA 加密

        /// <summary>
        /// SHA1 加密
        /// </summary>
        public static string Sha_1(this string source)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }
            var mEncoding = Encoding.UTF8;
            SHA1 mSHA1 = new SHA1CryptoServiceProvider();
            return HashAlgorithmBase(mSHA1, source, mEncoding);
        }

        /// <summary>
        /// SHA256 加密
        /// </summary>
        public static string Sha_256(this string source)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }
            var mEncoding = Encoding.UTF8;
            SHA256 mSHA256 = new SHA256Managed();
            return HashAlgorithmBase(mSHA256, source, mEncoding);
        }

        /// <summary>
        /// SHA384 加密
        /// </summary>
        public static string Sha_384(this string source)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }
            var mEncoding = Encoding.UTF8;
            SHA384 mSHA384 = new SHA384Managed();
            return HashAlgorithmBase(mSHA384, source, mEncoding);
        }

        /// <summary>
        /// SHA512 加密
        /// </summary>
        public static string Sha_512(this string source)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }
            var mEncoding = Encoding.UTF8;
            SHA512 mSHA512 = new SHA512Managed();
            return HashAlgorithmBase(mSHA512, source, mEncoding);
        }


        #endregion

        #region HMAC 加密

        /// <summary>
        /// HmacSha1 加密
        /// </summary>
        public static string HmacSha1(this string source, string keyVal)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }
            var mEncoding = Encoding.UTF8;
            byte[] keyStr = mEncoding.GetBytes(keyVal);
            HMACSHA1 mHMACSHA1 = new HMACSHA1(keyStr);

            return HashAlgorithmBase(mHMACSHA1, source, mEncoding);
        }

        /// <summary>
        /// HmacSha256 加密
        /// </summary>
        public static string HmacSha256(this string source, string keyVal)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }
            Encoding mEncoding = Encoding.UTF8;
            byte[] keyStr = Encoding.UTF8.GetBytes(keyVal);
            HMACSHA256 mHMACSHA256 = new HMACSHA256(keyStr);
            return HashAlgorithmBase(mHMACSHA256, source, mEncoding);
        }

        /// <summary>
        /// HmacSha384 加密
        /// </summary>
        public static string HmacSha384(this string source, string keyVal)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }
            Encoding mEncoding = Encoding.Default;
            byte[] keyStr = mEncoding.GetBytes(keyVal);
            HMACSHA384 hmacSha384_m = new HMACSHA384(keyStr);
            byte[] mmm = hmacSha384_m.ComputeHash(mEncoding.GetBytes(source));
            return BitConverter.ToString(mmm).Replace("-", "");
            //Return HashAlgorithmBase(hmacSha384_m, source, mEncoding)
        }

        /// <summary>
        /// HmacSha512 加密
        /// </summary>
        public static string HmacSha512(this string source, string keyVal)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }
            var mEncoding = Encoding.UTF8;
            byte[] keyStr = mEncoding.GetBytes(keyVal);
            HMACSHA512 hmacSha512_m = new HMACSHA512(keyStr);
            return HashAlgorithmBase(hmacSha512_m, source, mEncoding);
        }

        /// <summary>
        /// HmacMd5 加密
        /// </summary>
        public static string HmacMd5(this string source, string keyVal)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }
            var mEncoding = Encoding.UTF8;
            byte[] keyStr = mEncoding.GetBytes(keyVal);
            HMACMD5 hmacMd5_m = new HMACMD5(keyStr);
            return HashAlgorithmBase(hmacMd5_m, source, mEncoding);
        }
        public static string HmacMd5(this string source, byte[] keyVal)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }
            var mEncoding = Encoding.UTF8;
            //Dim keyStr As Byte() = mEncoding.GetBytes(keyVal)
            HMACMD5 hmacMd5_m = new HMACMD5(keyVal);
            return HashAlgorithmBase(hmacMd5_m, source, mEncoding);
        }
        /// <summary>
        /// HmacRipeMd160 加密
        /// </summary>
        public static string HmacRipeMd160(this string source, string keyVal)
        {
            if (string.IsNullOrEmpty(source))
            {
                return null;
            }
            var mEncoding = Encoding.UTF8;
            byte[] keyStr = mEncoding.GetBytes(keyVal);
            HMACRIPEMD160 hmacRipeMd160_m = new HMACRIPEMD160(keyStr);
            return HashAlgorithmBase(hmacRipeMd160_m, source, mEncoding);
        }

        #endregion

        #region BASE64 加密解密

        /// <summary>
        /// BASE64 加密
        /// </summary>
        /// <param name="source">待加密字段</param>
        /// <returns></returns>
        public static string Base64(this string source)
        {
            var btArray = Encoding.UTF8.GetBytes(source);
            return Convert.ToBase64String(btArray, 0, btArray.Length);
        }

        /// <summary>
        /// BASE64 解密
        /// </summary>
        /// <param name="source">待解密字段</param>
        /// <returns></returns>
        public static string UnBase64(this string source)
        {
            var btArray = Convert.FromBase64String(source);
            return Encoding.UTF8.GetString(btArray);
        }

        #endregion

        #region 内部方法

        /// <summary>
        /// 转成数组
        /// </summary>
        internal static byte[] Str2Bytes(this string source)
        {
            source = source.Replace(" ", "").Replace("-", "");
            byte[] buffer = new byte[source.Length / 2];
            for (int i = 0; i < source.Length; i += 2)
            {
                buffer[Convert.ToInt32(i / 2.0)] = Convert.ToByte(source.Substring(i, 2), 16);
            }
            return buffer;
        }

        /// <summary>
        /// 转换成字符串
        /// </summary>
        internal static string Bytes2Str(this IEnumerable<byte> source, string formatStr = "{0:X2}")
        {
            StringBuilder pwd = new StringBuilder();
            foreach (byte btStr in source)
            {
                pwd.AppendFormat(formatStr, btStr);
            }

            return pwd.ToString();

        }

        private static byte[] FormatByte(this string strVal, Encoding encoding)
        {
            return encoding.GetBytes(strVal);
        }

        /// <summary>
        /// HashAlgorithm 加密统一方法
        /// </summary>
        private static string HashAlgorithmBase(HashAlgorithm hashAlgorithmObj, string source, Encoding mEncoding)
        {
            byte[] btStr = mEncoding.GetBytes(source);
            byte[] hashStr = hashAlgorithmObj.ComputeHash(btStr);
            return hashStr.Bytes2Str();
        }

    }
    #endregion

}
