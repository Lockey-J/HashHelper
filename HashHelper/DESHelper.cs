using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace HashHelper
{

    #region DES 3DES加密解密类
    public class DESHelper
    {

        #region DES 加密解密

        /// <summary>
        /// DES加密
        /// </summary>
        /// <param name="source">待加密文本</param>
        /// <param name="mHashItem">设置DES加密参数</param>
        /// <returns></returns>
        public static string EncryptDes(string source, HashItem mHashItem)
        {
            byte[] mKey = null;
            byte[] mIV = null;
            mKey = mHashItem.HashEncoding.GetBytes(mHashItem.HashKey);
            mIV = mHashItem.HashEncoding.GetBytes(mHashItem.HashIV);
            return EncryptDes(source, mKey, mIV, mHashItem.HashMode, mHashItem.HashEncoding, mHashItem.HashPadding);
        }

        /// <summary>
        /// DES加密
        /// </summary>
        /// <param name="source"></param>
        /// <param name="aBKey"></param>
        /// <param name="mode"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static string EncryptDes(string source, byte[] aBKey, byte[] Iv, CipherMode mode, Encoding mEncoding, PaddingMode Padding)
        {
            try
            {
                DESCryptoServiceProvider des = new DESCryptoServiceProvider()
                {
                    Key = aBKey,
                    Mode = mode,
                    Padding = Padding
                };
                if (mode == CipherMode.CBC)
                {
                    des.IV = Iv;
                }
                ICryptoTransform desEncrypt = des.CreateEncryptor();
                byte[] buffer = mEncoding.GetBytes(source);
                byte[] resultBuff = desEncrypt.TransformFinalBlock(buffer, 0, buffer.Length);
                des.Clear();
                return resultBuff.Bytes2Str();
            }
            catch (Exception e)
            {
                return e.Message;
            }
        }


        /// <summary>
        /// DES 解密
        /// </summary>
        /// <param name="source">待解密文本</param>
        /// <param name="mHashItem">设置DES解密参数</param>
        /// <returns></returns>
        public static string DecryptDes(string source, HashItem mHashItem)
        {
            byte[] mKey = null;
            byte[] mIV = null;
            mKey = mHashItem.HashEncoding.GetBytes(mHashItem.HashKey);
            mIV = mHashItem.HashEncoding.GetBytes(mHashItem.HashIV);
            return DecryptDes(source, mKey, mIV, mHashItem.HashMode, mHashItem.HashEncoding, mHashItem.HashPadding);
        }
        /// <summary>
        /// DES解密默认UTF8编码
        /// </summary>
        /// <param name="source"></param>
        /// <param name="aBKey"></param>
        /// <param name="mode"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static string DecryptDes(string source, byte[] aBKey, byte[] Iv, CipherMode mode, Encoding mEncoding, PaddingMode Padding)
        {

            try
            {
                DESCryptoServiceProvider des = new DESCryptoServiceProvider()
                {
                    Key = aBKey,
                    Mode = mode,
                    Padding = Padding
                };
                if (mode == CipherMode.CBC)
                {
                    des.IV = Iv;
                }
                ICryptoTransform desDecrypt = des.CreateDecryptor();
                string result = string.Empty;
                byte[] buffer = Convert.FromBase64String(source);
                result = mEncoding.GetString(desDecrypt.TransformFinalBlock(buffer, 0, buffer.Length));
                return result;
            }
            catch (Exception e)
            {
                return e.Message;
            }
        }

        #endregion

        #region 3DES 加密解密
        /// <summary>
        /// 3des加密
        /// </summary>
        /// <param name="aStrString">待加密的字符串</param>
        /// <param name="mHashItem">HashItem加密参数类</param>
        /// <returns></returns>
        public static string Encrypt3Des(string aStrString, HashItem mHashItem)
        {
            byte[] mKey = null;
            byte[] mIV = null;
            mKey = mHashItem.HashEncoding.GetBytes(mHashItem.HashKey);
            mIV = mHashItem.HashEncoding.GetBytes(mHashItem.HashIV);
            return Encrypt3Des(aStrString, mKey, mIV, mHashItem.HashMode, mHashItem.HashEncoding, mHashItem.HashPadding);
        }
        /// <summary>
        /// 3DES加密
        /// </summary>
        /// <param name="aStrString">待加密文本</param>
        /// <param name="aStrKey">密钥数组</param>
        /// <param name="mode">填充方式</param>
        /// <param name="iv">向量数组</param>
        /// <returns></returns>
        public static string Encrypt3Des(string aStrString, byte[] aStrKey, byte[] iv, CipherMode mode, Encoding mEncoding, PaddingMode Padding)
        {
            try
            {
                TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider()
                {
                    Key = aStrKey,
                    Mode = mode,
                    Padding = Padding
                };
                if (mode == CipherMode.CBC)
                {
                    des.IV = iv;
                }
                ICryptoTransform desEncrypt = des.CreateEncryptor();
                byte[] buffer = mEncoding.GetBytes(aStrString);
                return Convert.ToBase64String(desEncrypt.TransformFinalBlock(buffer, 0, buffer.Length));
            }
            catch (Exception e)
            {
                return e.Message;
            }
        }


        /// <summary>
        /// 3des解密
        /// </summary>
        /// <param name="aStrString">待解密的字符串</param>
        /// <param name="mHashItem">HashItem加密参数类</param>
        /// <returns></returns>
        public static string Decrypt3Des(string aStrString, HashItem mHashItem)
        {
            byte[] mKey = null;
            byte[] mIV = null;
            mKey = mHashItem.HashEncoding.GetBytes(mHashItem.HashKey);
            mIV = mHashItem.HashEncoding.GetBytes(mHashItem.HashIV);
            return Decrypt3Des(aStrString, mKey, mIV, mHashItem.HashMode, mHashItem.HashEncoding, mHashItem.HashPadding);
        }

        /// <summary>
        /// 3des解密
        /// </summary>
        /// <param name="aStrString">加密密文</param>
        /// <param name="aStrKey">密钥数组</param>
        /// <param name="mode">填充方式</param>
        /// <param name="iv">向量数组</param>
        /// <returns></returns>
        public static string Decrypt3Des(string aStrString, byte[] aStrKey, byte[] iv, CipherMode mode, Encoding mEncoding, PaddingMode Padding)
        {
            try
            {
                TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider()
                {
                    Key = aStrKey,
                    Mode = mode,
                    Padding = Padding
                };
                if (mode == CipherMode.CBC)
                {
                    des.IV = iv;
                }
                ICryptoTransform desDecrypt = des.CreateDecryptor();
                string result = string.Empty;
                byte[] buffer = Convert.FromBase64String(aStrString);
                result = mEncoding.GetString(desDecrypt.TransformFinalBlock(buffer, 0, buffer.Length));
                return result;
            }
            catch (Exception e)
            {
                return e.Message;
            }
        }
        #endregion

    }
    #endregion

}
