using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace HashHelper
{
    #region AES加解密
    public class AESHelp
    {

        #region Aes加密

        /// <summary>  
        /// AES加密
        /// </summary>  
        /// <param name="SourceData">被加密的明文</param>  
        /// <param name="AesItem">设置AES参数</param>  
        /// <returns>密文</returns>  
        public static string AESEncrypt(string SourceData, HashItem AesItem)
        {
            return AESEncrypt(SourceData, AesItem.HashKey, AesItem.HashIV, AesItem.HashMode, AesItem.HashEncoding, AesItem.HashPadding, AesItem.AesKeySize);
        }

        /// <summary>
        /// Aes加密
        /// </summary>
        /// <param name="SourceData">待加密文本</param>
        /// <param name="Key">Aes密钥文本</param>
        /// <param name="Iv">IV向量文本</param>
        /// <param name="AesMode">电子密钥模式</param>
        /// <param name="mEncoding">字符编码</param>
        /// <param name="mPaddingMode">填充模式</param>
        /// <param name="mKeySzie">加密长度</param>
        /// <returns>返回Base64字符文本</returns>
        public static string AESEncrypt(string SourceData, string Key, string Iv, CipherMode AesMode, Encoding mEncoding, PaddingMode mPaddingMode, int mKeySzie)
        {
            MemoryStream mStream = new MemoryStream();
            RijndaelManaged AES = new RijndaelManaged();

            byte[] plainBytes = mEncoding.GetBytes(SourceData);
            byte[] bKey = new byte[32];
            Array.Copy(mEncoding.GetBytes(Key.PadRight(bKey.Length, '0')), bKey, bKey.Length);

            AES.Mode = AesMode;
            AES.Padding = mPaddingMode;
            AES.KeySize = mKeySzie;

            AES.Key = bKey;
            if (AesMode == CipherMode.CBC)
            {
                byte[] bIv = new byte[16];
                Array.Copy(mEncoding.GetBytes(Iv.PadRight(bIv.Length, '0')), bIv, bIv.Length);
                AES.IV = bIv;
            }

            CryptoStream cryptoStream = new CryptoStream(mStream, AES.CreateEncryptor(), CryptoStreamMode.Write);
            try
            {
                cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                cryptoStream.FlushFinalBlock();
                return Convert.ToBase64String(mStream.ToArray());
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
            finally
            {
                cryptoStream.Close();
                mStream.Close();
                AES.Clear();
            }
        }
        #endregion

        #region Aes解密
        /// <summary>  
        /// AES加密
        /// </summary>  
        /// <param name="SourceData">待解密的明文</param>  
        /// <param name="AesItem">设置AES参数</param>  
        /// <returns>原文字符文本</returns>  
        public static string AesDecrypt(string SourceData, HashItem AesItem)
        {
            return AesDecrypt(SourceData, AesItem.HashKey, AesItem.HashIV, AesItem.HashMode, AesItem.HashEncoding, AesItem.HashPadding, AesItem.AesKeySize);
        }
        /// <summary>
        /// Aes解密
        /// </summary>
        /// <param name="SourceData">待解密文本</param>
        /// <param name="Key">Aes密钥文本</param>
        /// <param name="Iv">IV向量文本</param>
        /// <param name="AesMode">电子密钥模式</param>
        /// <param name="mEncoding">字符编码</param>
        /// <param name="mPaddingMode">填充模式</param>
        /// <param name="mKeySzie">加密长度</param>
        /// <returns></returns>
        public static string AesDecrypt(string SourceData, string Key, string Iv, CipherMode AesMode, Encoding mEncoding, PaddingMode mPaddingMode, int mKeySzie)
        {
            byte[] encryptedBytes = Convert.FromBase64String(SourceData);
            MemoryStream mStream = new MemoryStream();
            RijndaelManaged AES = new RijndaelManaged();
            byte[] bKey = new byte[32];
            Array.Copy(mEncoding.GetBytes(Key.PadRight(bKey.Length, '0')), bKey, bKey.Length);
            AES.Mode = AesMode;
            AES.Padding = mPaddingMode;
            AES.KeySize = mKeySzie;
            AES.Key = bKey;
            if (AesMode == CipherMode.CBC)
            {
                byte[] bIv = new byte[16];
                Array.Copy(mEncoding.GetBytes(Iv.PadRight(bIv.Length, '0')), bIv, bIv.Length);
                AES.IV = bIv;
            }
            CryptoStream cryptoStream = new CryptoStream(mStream, AES.CreateDecryptor(), CryptoStreamMode.Read);
            try
            {
                byte[] tmp = new byte[encryptedBytes.Length + 32];
                int len = cryptoStream.Read(tmp, 0, encryptedBytes.Length + 32);
                byte[] ret = new byte[len];
                Array.Copy(tmp, 0, ret, 0, len);
                return mEncoding.GetString(ret);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
            finally
            {
                cryptoStream.Close();
                mStream.Close();
                AES.Clear();
            }
        }
        #endregion

    }
    #endregion

}
