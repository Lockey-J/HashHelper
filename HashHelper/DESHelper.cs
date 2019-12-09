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
            if (string.IsNullOrWhiteSpace(source))
            {
                return string.Empty;
            }
            byte[] mKey = mHashItem.HashEncoding.GetBytes(mHashItem.HashKey);
            byte[] mIV = mHashItem.HashEncoding.GetBytes(mHashItem.HashIV);
            byte[] buffer = mHashItem.HashEncoding.GetBytes(source);

            return Convert.ToBase64String(EncryptDes(buffer, mKey, mIV, mHashItem.HashMode,  mHashItem.HashPadding));
        }


        /// <summary>
        /// DES加密
        /// </summary>
        /// <param name="source">待加密数组</param>
        /// <param name="aBKey">密钥</param>
        /// <param name="Iv">向量</param>
        /// <param name="mode">加密模式</param>
        /// <param name="Padding">填充模式</param>
        /// <returns></returns>
        public static byte[] EncryptDes(byte[] source, byte[] aBKey, byte[] Iv, CipherMode mode,  PaddingMode Padding)
        {
            try
            {
                if (source == null)
                    return null;
                using (DESCryptoServiceProvider des = new DESCryptoServiceProvider()
                {
                    Key = aBKey,
                    Mode = mode,
                    Padding = Padding
                })
                {
                    if (mode != CipherMode.ECB)
                    {
                        des.IV = Iv;
                    }
                    ICryptoTransform desEncrypt = des.CreateEncryptor();                    
                    byte[] resultBuff = desEncrypt.TransformFinalBlock(source, 0, source.Length);
                    des.Clear();
                    return resultBuff;
                }
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
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
            if (string.IsNullOrWhiteSpace(source))
            {
                return string.Empty;
            }
            byte[] buffer = Convert.FromBase64String(source);
            byte[] mKey = mHashItem.HashEncoding.GetBytes(mHashItem.HashKey);
            byte[] mIV = mHashItem.HashEncoding.GetBytes(mHashItem.HashIV);
            return mHashItem.HashEncoding.GetString(DecryptDes(buffer, mKey, mIV, mHashItem.HashMode,  mHashItem.HashPadding));
        }
     

        public static byte[] DecryptDes(byte[] source, byte[] aBKey, byte[] Iv, CipherMode mode,  PaddingMode Padding)
        {

            try
            {
                using (DESCryptoServiceProvider des = new DESCryptoServiceProvider()
                {
                    Key = aBKey,
                    Mode = mode,
                    Padding = Padding
                })
                {
                    if (mode != CipherMode.ECB)
                    {
                        des.IV = Iv;
                    }
                    ICryptoTransform desDecrypt = des.CreateDecryptor();
                    return desDecrypt.TransformFinalBlock(source, 0, source.Length);
                }

            }
            catch (Exception e)
            {
               throw new Exception(e.Message);
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
        public static string Encrypt3Des(string source, HashItem mHashItem)
        {
            if (string.IsNullOrWhiteSpace(source))
            {
                return string.Empty;
            }
            byte[] buffer = mHashItem.HashEncoding.GetBytes(source);
            byte[] mKey = mHashItem.HashEncoding.GetBytes(mHashItem.HashKey);
            byte[] mIV = mHashItem.HashEncoding.GetBytes(mHashItem.HashIV);
            return Convert.ToBase64String(Encrypt3Des(buffer, mKey, mIV, mHashItem.HashMode,  mHashItem.HashPadding));
        }
        /// <summary>
        /// 3DES加密
        /// </summary>
        /// <param name="source">待加密文本</param>
        /// <param name="aStrKey">密钥数组</param>
        /// <param name="mode">填充方式</param>
        /// <param name="iv">向量数组</param>
        /// <returns></returns>
        public static byte[] Encrypt3Des(byte[] source, byte[] aStrKey, byte[] iv, CipherMode mode, PaddingMode Padding)
        {
            try
            {
                using (TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider()
                {
                    Key = aStrKey,
                    Mode = mode,
                    Padding = Padding
                })
                {
                    if (mode != CipherMode.ECB)
                    {
                        des.IV = iv;
                    }
                    ICryptoTransform desEncrypt = des.CreateEncryptor();
                   
                    return desEncrypt.TransformFinalBlock(source, 0, source.Length);
                }

            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }


        /// <summary>
        /// 3des解密
        /// </summary>
        /// <param name="source">待解密的字符串</param>
        /// <param name="mHashItem">HashItem加密参数类</param>
        /// <returns></returns>
        public static string Decrypt3Des(string source, HashItem mHashItem)
        {
            if (string.IsNullOrWhiteSpace(source))
            {
                return string.Empty;
            }
            byte[] buffer = Convert.FromBase64String(source);
            byte[] mKey = mHashItem.HashEncoding.GetBytes(mHashItem.HashKey);
            byte[] mIV = mHashItem.HashEncoding.GetBytes(mHashItem.HashIV);
            return mHashItem.HashEncoding.GetString(Decrypt3Des(buffer, mKey, mIV, mHashItem.HashMode,  mHashItem.HashPadding));
        }

        /// <summary>
        /// 3des解密
        /// </summary>
        /// <param name="source">加密密文</param>
        /// <param name="aStrKey">密钥数组</param>
        /// <param name="mode">填充方式</param>
        /// <param name="iv">向量数组</param>
        /// <returns></returns>
        public static byte[] Decrypt3Des(byte[] source, byte[] aStrKey, byte[] iv, CipherMode mode, PaddingMode Padding)
        {
            try
            {
                using (TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider()
                {
                    Key = aStrKey,
                    Mode = mode,
                    Padding = Padding
                })
                {
                    if (mode != CipherMode.ECB)
                    {
                        des.IV = iv;
                    }
                    ICryptoTransform desDecrypt = des.CreateDecryptor();
                    string result = string.Empty;
                    
                   
                    return desDecrypt.TransformFinalBlock(source, 0, source.Length);
                }
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }
        #endregion

    }
    #endregion

}

