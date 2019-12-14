using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace AWSSignatureV4
{
    public class SignV4
    {
        private string AWSAccessKey;
        private string AWSSecret;
        private string Region;

        public SignV4(string AWSAccessKey, string AWSSecret, string Region)
        {
            this.AWSAccessKey = AWSAccessKey;
            this.AWSSecret = AWSSecret;
            this.Region = Region;
        }

        public string SignS3Get(DateTime date, Uri uri)
        {
            string service = "s3";

            //Canonical Request
            string HTTPMethod = "GET" + "\n";
            string CanonicalURI = UriEncode(uri.AbsolutePath, false) + "\n";
            string CanonicalQuerystring = "" + "\n";
            string CanonicalHeaders = "host:" + uri.Host + "\n"
            + "x-amz-content-sha256:" + SHA256Hash("") + "\n"
            + "x-amz-date:" + date.ToString("yyyyMMddTHHmmssZ") + "\n";
            string SignedHeaders = "host;x-amz-content-sha256;x-amz-date";
            string HashedPayload = SHA256Hash("");

            string CanonicalRequest = HTTPMethod + CanonicalURI + CanonicalQuerystring + CanonicalHeaders + "\n" + SignedHeaders + "\n" + HashedPayload;

            //StringToSign
            string StringToSignStart = "AWS4-HMAC-SHA256" + "\n";
            string TimeStamp = date.ToString("yyyyMMddTHHmmssZ") + "\n";
            string Scope = date.ToString("yyyyMMdd") + "/" + Region + "/" + service + "/aws4_request" + "\n";

            string StringToSign = StringToSignStart + TimeStamp + Scope + SHA256Hash(CanonicalRequest);

            //Signature
            string firstKey = "AWS4" + AWSSecret;
            Byte[] DateKey = HMACSHA256Hash(Encoding.UTF8.GetBytes(firstKey), Encoding.UTF8.GetBytes(date.ToString("yyyyMMdd")));
            Byte[] DateRegionKey = HMACSHA256Hash(DateKey, Encoding.UTF8.GetBytes(Region));
            Byte[] DateRegionServiceKey = HMACSHA256Hash(DateRegionKey, Encoding.UTF8.GetBytes(service));
            Byte[] SigningKey = HMACSHA256Hash(DateRegionServiceKey, Encoding.UTF8.GetBytes("aws4_request"));

            var signature = HMACSHA256Hash(SigningKey, Encoding.UTF8.GetBytes(StringToSign));
            string ssignature = BitConverter.ToString(signature).Replace("-", "").ToLower();



            string AuthorizationHeader = "Credential=" + AWSAccessKey + "/" + date.ToString("yyyyMMdd") + "/" + Region + "/" + service + "/aws4_request,"
                + " SignedHeaders=" + SignedHeaders + ", Signature=" + ssignature;

            return AuthorizationHeader;

        }

        public string SignFirehosePost(DateTime date, Uri uri, string payload)
        {
            string service = "firehose";

            //Canonical Request
            string HTTPMethod = "POST" + "\n";
            string CanonicalURI = UriEncode(uri.AbsolutePath, false) + "\n";
            string CanonicalQuerystring = "" + "\n";
            string CanonicalHeaders = "host:" + uri.Host + "\n"
            + "x-amz-date:" + date.ToString("yyyyMMddTHHmmssZ") + "\n"
            + "x-amz-target:Firehose_20150804.PutRecord\n";
            string SignedHeaders = "host;x-amz-date;x-amz-target";
            string HashedPayload = SHA256Hash(payload);

            string CanonicalRequest = HTTPMethod + CanonicalURI + CanonicalQuerystring + CanonicalHeaders + "\n" + SignedHeaders + "\n" + HashedPayload;

            //StringToSign
            string StringToSignStart = "AWS4-HMAC-SHA256" + "\n";
            string TimeStamp = date.ToString("yyyyMMddTHHmmssZ") + "\n";
            string Scope = date.ToString("yyyyMMdd") + "/" + Region + "/" + service + "/aws4_request" + "\n";

            string StringToSign = StringToSignStart + TimeStamp + Scope + SHA256Hash(CanonicalRequest);

            ////Signature
            string firstKey = "AWS4" + AWSSecret;
            Byte[] DateKey = HMACSHA256Hash(Encoding.UTF8.GetBytes(firstKey), Encoding.UTF8.GetBytes(date.ToString("yyyyMMdd")));
            Byte[] DateRegionKey = HMACSHA256Hash(DateKey, Encoding.UTF8.GetBytes(Region));
            Byte[] DateRegionServiceKey = HMACSHA256Hash(DateRegionKey, Encoding.UTF8.GetBytes(service));
            Byte[] SigningKey = HMACSHA256Hash(DateRegionServiceKey, Encoding.UTF8.GetBytes("aws4_request"));
                       
            var signature = HMACSHA256Hash(SigningKey, Encoding.UTF8.GetBytes(StringToSign));
            string ssignature = BitConverter.ToString(signature).Replace("-", "").ToLower();
                       
            string AuthorizationHeader = "Credential=" + AWSAccessKey + "/" + date.ToString("yyyyMMdd") + "/" + Region + "/" + service + "/aws4_request,"
                + " SignedHeaders=" + SignedHeaders + ", Signature=" + ssignature;

            return AuthorizationHeader;

        }


        public HttpRequestMessage CreateS3GetRequest(DateTime Date, Uri uri)
        {
            HttpRequestMessage requestMessage = new HttpRequestMessage(HttpMethod.Get, uri);

            // Add our custom headers
            requestMessage.Headers.Add("host", uri.Host);
            requestMessage.Headers.Add("x-amz-date", Date.ToString("yyyyMMddTHHmmssZ"));
            requestMessage.Headers.Add("x-amz-content-sha256", SHA256Hash(""));
            requestMessage.Version = Version.Parse("1.1");

            return requestMessage;
        }


        public HttpRequestMessage CreateFirehosePostRequest(DateTime Date, Uri uri, string payload)
        {
            HttpRequestMessage requestMessage = new HttpRequestMessage(HttpMethod.Post, uri);

            // Add our custom headers
            requestMessage.Headers.Add("host", uri.Host);
            requestMessage.Headers.Add("x-amz-date", Date.ToString("yyyyMMddTHHmmssZ"));
            requestMessage.Headers.Add("x-amz-target", "Firehose_20150804.PutRecord");
            requestMessage.Version = Version.Parse("1.1");
            requestMessage.Content = new StringContent(payload, Encoding.UTF8, "application/x-amz-json-1.1");

            return requestMessage;
        }

        private static string Hex(string text)
        {
            char[] values = text.ToCharArray();
            StringBuilder builder = new StringBuilder();
            foreach (char letter in values)
            {
                // Get the integral value of the character.
                int value = Convert.ToInt32(letter);
                // Convert the integer value to a hexadecimal value in string form.
                builder.Append($"{value:X}");
            }
            return builder.ToString();
        }


        private string SHA256Hash(string text)
        {
            SHA256 sha256Hash = SHA256.Create();
            // ComputeHash - returns byte array  
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(text));

            // Convert byte array to a string   
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();

        }

        private string HMACSHA256Hash(string key, string text)
        {
            var encoding = Encoding.UTF8;

            Byte[] textBytes = encoding.GetBytes(text);
            Byte[] keyBytes = encoding.GetBytes(key);

            Byte[] hashBytes;

            using (HMACSHA256 hash = new HMACSHA256(keyBytes))
                hashBytes = hash.ComputeHash(textBytes);

            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }


        private Byte[] HMACSHA256Hash(Byte[] key, Byte[] text)
        {
            var encoding = Encoding.UTF8;

            Byte[] hashBytes;

            using (HMACSHA256 hash = new HMACSHA256(key))
                hashBytes = hash.ComputeHash(text);

            return hashBytes;
        }

        private string toHexUTF8(string text)
        {
            byte[] bytes = Encoding.Default.GetBytes(text);
            return Hex(Encoding.UTF8.GetString(bytes));
        }

        private string UriEncode(string input, bool encodeSlash)
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < input.Length; i++)
            {
                char ch = input[i];
                if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '~' || ch == '.')
                {
                    result.Append(ch);
                }
                else if (ch == '/')
                {
                    result.Append(encodeSlash ? "%2F" : ch.ToString());
                }
                else
                {
                    result.Append(toHexUTF8(ch.ToString()));
                }
            }
            return result.ToString();
        }
    }
}
