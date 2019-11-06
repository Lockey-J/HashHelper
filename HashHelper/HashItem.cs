using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace HashHelper
{
    #region Hash参数设置
    /// <summary>
    /// 设置Hash的Key,IV,Mode,Encoding
    /// </summary>

    public class HashItem
    {

        #region DES加密参数变量
        public string HashKey { get; set; } = "1234567812345678";
        public string HashIV { get; set; } = "1234567812345678";
        public Encoding HashEncoding { get; set; } = Encoding.UTF8;
        public CipherMode HashMode { get; set; } = CipherMode.ECB;
        public PaddingMode HashPadding { get; set; } = PaddingMode.PKCS7;
        public int AesKeySize { get; set; } = 128;

        #endregion

        #region RSA参数设置
        /// <summary>
        /// RSA公钥
        /// </summary>
        /// <returns></returns>
        public string PublicRsaKey { get; set; }

        /// <summary>
        /// RSA私钥
        /// </summary>
        /// <returns></returns>
        public string PrivateRsaKey { get; set; }

        /// <summary>
        /// Rsa_n
        /// </summary>
        /// <returns></returns>
        public string RsaModulus { get; set; }

        /// <summary>
        /// Rsa_e
        /// </summary>
        /// <returns></returns>
        public string RsaExponent { get; set; }
        #endregion
    }
#endregion

}
