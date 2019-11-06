using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace HashHelper
{
    #region Rsa加密类
    public class RsaHelp
    {

        /// <summary>
        /// Rsa加密
        /// </summary>
        /// <param name="Source">待加密文本</param>
        /// <param name="RsaItem">Rsa设置参数</param>
        /// <returns>返回Base64密文</returns>
        public static string EncryptRsa(string Source, HashItem RsaItem)
        {
            RSACryptoServiceProvider mRsa = new RSACryptoServiceProvider();
            Encoding mEncoding = RsaItem.HashEncoding;
            if (!string.IsNullOrWhiteSpace(RsaItem.PublicRsaKey))
            {
                mRsa.FromXmlString(RsaItem.PublicRsaKey);
            }
            else if (!string.IsNullOrWhiteSpace(RsaItem.RsaModulus))
            {
                byte[] Rsa_N = RsaItem.RsaModulus.Str2Bytes();
                byte[] Rsa_E = RsaItem.RsaExponent.PadLeft(6, '0').Str2Bytes();
                RSAParameters mRSAParameters = new RSAParameters
                {
                    Modulus = Rsa_N,
                    Exponent = Rsa_E
                };
                mRsa.ImportParameters(mRSAParameters);
            }
            else
            {
                return Source;
            }

            byte[] cipherbytes = mRsa.Encrypt(mEncoding.GetBytes(Source), false);
            return Convert.ToBase64String(cipherbytes);
        }


        /// <summary>
        /// Rsa解密
        /// </summary>
        /// <param name="Source">待解密的密文</param>
        /// <param name="RsaItem">Rsa设置参数</param>
        /// <returns>返回解密后文本</returns>
        public static string DecryptRsa(string Source, HashItem RsaItem)
        {
            RSACryptoServiceProvider mRsa = new RSACryptoServiceProvider();
            Encoding mEncoding = RsaItem.HashEncoding;
            if (!string.IsNullOrWhiteSpace(RsaItem.PublicRsaKey))
            {
                mRsa.FromXmlString(RsaItem.PublicRsaKey);
            }
            else if (!string.IsNullOrWhiteSpace(RsaItem.RsaModulus))
            {
                byte[] Rsa_N = RsaItem.RsaModulus.Str2Bytes();
                byte[] Rsa_E = RsaItem.RsaExponent.PadLeft(6, '0').Str2Bytes();
                RSAParameters mRSAParameters = new RSAParameters
                {
                    Modulus = Rsa_N,
                    Exponent = Rsa_E
                };
                mRsa.ImportParameters(mRSAParameters);
            }
            else
            {
                return Source;
            }
            var cipherbytes = mRsa.Decrypt(Convert.FromBase64String(Source), false);
            return mEncoding.GetString(cipherbytes);
        }
    }
    #endregion
}
