using System;
using System.IO;
using System.Net.Http;
using Xunit;

namespace AWSSignatureV4.Test
{
    public class UnitTest1
    {
        string AWSAccessKey;
        string AWSSecret;

        public UnitTest1()
        {
            var apiKeys = File.ReadAllText("AWS.key").Split(',');
            AWSAccessKey = apiKeys[0];
            AWSSecret = apiKeys[1];
        }

        [Fact]
        public void S3GetTest()
        {
            var uri = new Uri("https://s3.eu-central-1.amazonaws.com/image4io.user.development/i4io/1e671983-3ffb-4c3b-87d1-40cfe348d72a.jpg");
            var date = DateTime.UtcNow;

            var signv4 = new SignV4(AWSAccessKey, AWSSecret, "eu-central-1");

            var client = new HttpClient();
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("AWS4-HMAC-SHA256", signv4.SignS3Get(date, uri));

            var result = client.SendAsync(signv4.CreateS3GetRequest(date, uri)).GetAwaiter().GetResult();
            var response = result.Content.ReadAsStringAsync().GetAwaiter().GetResult();

            Assert.Equal(System.Net.HttpStatusCode.OK, result.StatusCode);
        }

        [Fact]
        public void FirehosePutRecordTest()
        {
            var uri = new Uri("https://firehose.eu-west-1.amazonaws.com");
            var date = DateTime.UtcNow;

            var signv4 = new SignV4(AWSAccessKey, AWSSecret, "eu-west-1");
            string payload = "{\"DeliveryStreamName\":\"i4io-log-test-2\",\"Record\":{\"Data\":\"AA\"}}";

            var client = new HttpClient();
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("AWS4-HMAC-SHA256", signv4.SignFirehosePost(date, uri, payload));

            var result = client.SendAsync(signv4.CreateFirehosePostRequest(date, uri, payload)).GetAwaiter().GetResult();
            var response = result.Content.ReadAsStringAsync().GetAwaiter().GetResult();

            Assert.Equal(System.Net.HttpStatusCode.OK, result.StatusCode);
        }
    }
}
