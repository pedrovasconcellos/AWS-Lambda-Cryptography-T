using System;
using Vasconcellos.Crypt;
using Amazon.Lambda.Core;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace AWSLambdaCryptography
{
    public class Function
    {

        /// <summary>
        /// Encryption algorithm AES
        /// </summary>
        /// <param name="request"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public dynamic FunctionHandler(Request request, ILambdaContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            if (request == null || request.Data == null)
                throw new ArgumentNullException(nameof(request));

            var key = CryptographyAES.GenerateKey();
            var iv = CryptographyAES.GenerateIV();
            var bits = CryptographyAES.BitsEnum.bit256;
            var AES = new CryptographyAES(key, iv, bits);

            var data = SetTyping(request.Data);
            var encrypted = AES.Encrypt(data);
            context.Logger.Log("Encrypted message.");

            return new Response(key, iv, (short)bits, encrypted);
        }

        internal dynamic SetTyping(dynamic inputData)
        {
            dynamic data = inputData is string ? inputData : default(byte[]);

            if (data == null)
            {
                int index = 0;
                byte[] bytes = new byte[inputData.Count];
                foreach (var item in inputData)
                {
                    bytes[index++] = (byte)item.Value;
                }
                data = bytes;
            }
            return data;
        }

        public class Request
        {
            public dynamic Data { get; set; }
        }

        public class Response
        {
            public Response(string key, byte[] iv, short bits, dynamic encrypted)
            {
                this.Key = key;
                this.IV = iv;
                this.Bits = bits;
                this.Encrypted = encrypted;
            }

            public string Key { get; set; }
            public byte[] IV { get; set; }
            public short Bits { get; set; }
            public dynamic Encrypted { get; set; }
        }
    }
}
