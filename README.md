# aws_cloudfront_signed_url

Create a signed AWS CloudFront URL using a custom policy

## Example

```
final String privateKey = """-----BEGIN RSA PRIVATE KEY-----
Key123
-----END RSA PRIVATE KEY-----""";
String url = 'http://d111111abcdef8.cloudfront.net/images/horizon.jpg';
String cloudFrontSignedUrl = await AWSCloudFrontSignedUrl(
  keyPairId: "K2JCJMDEHXQW5F",
  privateKey: privateKey,
).signUrl(
  resourceUrl: url,
  ipAddress: "0.0.0.0/32",
  dateLessThan: DateTime(2022,3,1),
  dateGreaterThan: DateTime(2021,3,1),
);
```
